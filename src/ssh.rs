use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use russh::*;
use russh_keys::key::PublicKey;
use termion::raw::IntoRawMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

// TODO: Snippet for interactive shell
/*
*/

struct Handler {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Handler {
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
    session: client::Handle<Handler>,
}

impl Session {
    pub async fn connect<A: ToSocketAddrs>(user: &str, pass: &str, addrs: A) -> Result<Self> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(86400)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let handler = Handler {};

        let mut session = client::connect(config, addrs, handler).await?;

        let auth_res = session.authenticate_password(user, pass).await?;
        if !auth_res {
            anyhow::bail!("Authentication (with password) failed");
        }

        Ok(Self { session })
    }

    pub async fn run_script(&mut self, command: String, capture: bool) -> Result<(u32, Vec<u8>)> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut code = 0;
        let mut buffer: Vec<u8> = Vec::new();
        let mut stdout = tokio::io::stdout();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    buffer.extend_from_slice(data);
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = exit_status;
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }

        Ok((code, buffer))
    }

    pub async fn shell(&mut self) -> Result<u32> {
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

        channel.request_shell(true).await?;

        let code;
        let mut stdin = tokio_fd::AsyncFd::try_from(0)?;
        let mut stdout = tokio_fd::AsyncFd::try_from(1)?;
        let mut buf = vec![0; 1024];
        let mut stdin_closed = false;

        let _raw_term = std::io::stdout().into_raw_mode()?;

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
