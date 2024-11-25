use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use crossterm::terminal;
use russh::*;
use russh_keys::key::PublicKey;
use russh_sftp::client::SftpSession;
use tokio::fs::File;
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

    // We don't care about the server key being recognized
    // Need as little interactive input as possible
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

#[derive(Debug, Clone)]
pub enum Runnable {
    Script(PathBuf),
    Command(String),
}

impl Session {
    pub async fn connect<A: ToSocketAddrs>(
        user: &str,
        pass: &str,
        addrs: A,
    ) -> anyhow::Result<Self> {
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

    pub async fn upload(&mut self, file: &Path) -> anyhow::Result<String> {
        let mut src = File::open(file).await?;
        let filename = file
            .file_name()
            .ok_or_else(|| anyhow::Error::msg("couldn't find filename for script path"))?
            .to_str()
            .ok_or_else(|| anyhow::Error::msg("couldn't convert filename to string"))?;
        let sftp_channel = self.session.channel_open_session().await?;
        sftp_channel
            .request_subsystem(true, "sftp")
            .await
            .context("couldn't request sftp subsystem")?;
        let sftp = SftpSession::new(sftp_channel.into_stream()).await?;
        let mut dst = sftp.create(filename).await?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .context("couldn't copy file to remote location")?;
        Ok(filename.into())
    }

    pub async fn exec(&mut self, run: Runnable, capture: bool) -> anyhow::Result<(u32, Vec<u8>)> {
        let cmd = match run {
            Runnable::Script(file) => {
                format!("sh {}", self.upload(&file).await?)
            }
            Runnable::Command(cmd) => cmd,
        };
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, cmd).await?;

        let mut code = 0;
        let mut buffer: Vec<u8> = Vec::new();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    if capture {
                        buffer.extend_from_slice(data);
                    }
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

    pub async fn shell(&mut self) -> anyhow::Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // This example doesn't terminal resizing after the connection is established
        let (w, h) = terminal::size()?;

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
        // let mut events = EventStream::new();
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut stdin_closed = false;
        let mut buf = [0; 1000];

        terminal::enable_raw_mode()?;

        loop {
            // let next = events.next().fuse();
            // Handle one of the possible events:
            tokio::select! {
                // There's terminal input available from the user
                /*
                update = next => {
                    match update {
                        Some(Ok(event)) => {
                            match event {
                                Event::Key(key) => {
                                    match key.code {
                                        KeyCode::Char(c) => {
                                            let mut buf = [0; 4];
                                            c.encode_utf8(&mut buf);
                                            channel.data(&buf[..]).await?;
                                        },
                                        KeyCode::Backspace => {
                                        },
                                        // IDRC
                                        _ => {}
                                    }
                                }
                                // IDRC
                                _ => continue,
                            }
                        },
                        Some(Err(err)) => return Err(err.into()),
                        None => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                    }
                }
                */
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

        terminal::disable_raw_mode()?;

        Ok(code)
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
