use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use russh::*;
use russh_keys::key::PublicKey;
use termion::raw::IntoRawMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

mod nmap;

#[tokio::main]
async fn main() -> Result<()> {
    // CLI options are defined later in this file
    let cli = Cli::parse();

    println!("Connecting to {}:{}", cli.host, 22);

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(cli.user, cli.pass, (cli.host, 22)).await?;
    println!("Connected");

    let code = {
        // We're using `termion` to put the terminal into raw mode, so that we can
        // display the output of interactive applications correctly
        let _raw_term = std::io::stdout().into_raw_mode()?;
        ssh.call(&cli.command).await?
    };

    println!("Exitcode: {:?}", code);
    ssh.close().await?;
    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper
/// around a russh client
/// that handles the input/output event loop
pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<A: ToSocketAddrs>(
        user: impl Into<String>,
        pass: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(86400)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = client::connect(config, addrs, sh).await?;

        let auth_res = session.authenticate_password(user, pass).await?;
        if !auth_res {
            anyhow::bail!("Authentication (with password) failed");
        }

        // use publickey authentication, with or without certificate
        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // This example doesn't terminal resizing after the connection is established
        let (w, h) = termion::terminal_size()?;

        // Request an interactive PTY from the server
        channel
            .request_pty(
                false,
                "xterm".into(),
                w as u32,
                h as u32,
                0,
                0,
                &[], // ideally you want to pass the actual terminal modes here
            )
            .await?;
        /*
        channel.exec(true, command).await?;
        */
        channel.request_shell(true).await?;

        let code;
        let mut stdin = tokio_fd::AsyncFd::try_from(0)?;
        let mut stdout = tokio_fd::AsyncFd::try_from(1)?;
        let mut buf = vec![0; 1024];
        let mut stdin_closed = false;

        loop {
            // Handle one of the possible events:
            tokio::select! {
                // There's terminal input available from the user
                r = stdin.read(&mut buf), if !stdin_closed => {
                    match r {
                        Ok(0) => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the terminal
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        // The command has returned an exit code
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            if !stdin_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }
        Ok(code)
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

#[derive(clap::Parser)]
pub struct Cli {
    host: String,
    user: String,
    pass: String,
    command: String,
}
