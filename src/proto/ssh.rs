use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::scripts::Scripts;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use crossterm::terminal;
use russh::*;
use russh_keys::key::PublicKey;
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc;

struct Handler;

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

impl Session {
    pub async fn connect<A: ToSocketAddrs>(
        user: &str,
        pass: &str,
        addrs: A,
    ) -> anyhow::Result<Self> {
        let config = client::Config {
            // Don't want the inactivity to kill the session from our side
            // inactivity_timeout: Some(Duration::from_secs(86400)),
            keepalive_interval: Some(Duration::from_secs(1)),
            // Tolerate only 10 seconds of frozen terminal before failing
            keepalive_max: 10,
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

    // Read the first line of the server, which prints the ID
    async fn do_read_server_id<A: ToSocketAddrs>(addrs: A) -> anyhow::Result<String> {
        // This should take a really short amount of time because it's just connecting
        let stream = tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(addrs))
            .await
            .context("timed out")?
            .context("failed to connect to tcp stream")?;
        stream.readable().await?;
        let mut data = vec![0; 1024];
        let count = stream.try_read(&mut data)?;
        Ok(String::from_utf8_lossy(&data[..count]).into())
    }

    pub async fn get_server_id<A: ToSocketAddrs>(
        addrs: A,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        tokio::time::timeout(timeout, Self::do_read_server_id(addrs)).await?
    }

    pub async fn upload(&mut self, file: &Path) -> anyhow::Result<String> {
        let filename = PathBuf::from(file)
            .file_name()
            .ok_or(anyhow!("couldn't find filename for script"))?
            .to_string_lossy()
            .into_owned();
        let mut src = Scripts::find(file)
            .await
            .ok_or(anyhow!("couldn't find script"))?;
        let sftp_channel = self.session.channel_open_session().await?;
        sftp_channel
            .request_subsystem(true, "sftp")
            .await
            .context("couldn't request sftp subsystem")?;
        let sftp = SftpSession::new(sftp_channel.into_stream()).await?;
        let mut dst = sftp.create(&filename).await?;
        let mut meta = dst.metadata().await?;
        // rwx------
        meta.permissions = Some(0o700);
        dst.set_metadata(meta)
            .await
            .context("couldn't change file permissions")?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .context("couldn't copy file to remote location")?;
        sftp.close().await?;
        Ok(filename.into())
    }

    pub async fn exec(&mut self, command: String, capture: bool) -> anyhow::Result<(u32, Vec<u8>)> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
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

    // WARNING: This does NOT handle shell escaping!!! Be careful!!!
    pub async fn run_script(
        &mut self,
        script: &Path,
        args: Vec<String>,
        capture: bool,
        upload: bool,
    ) -> anyhow::Result<(u32, Vec<u8>)> {
        let script = self.upload(&script).await?;
        let script = format!("./{}", script);
        let cmd = shlex::try_join(
            std::iter::once(&script)
                .chain(args.iter())
                .map(String::as_str),
        )?;
        log::info!("{}", cmd);
        let (code, output) = self.exec(cmd, capture).await?;
        if !upload {
            self.exec(format!("rm {}", script), false).await?;
        }
        Ok((code, output))
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
        let (stdin_sender, mut stdin) = mpsc::channel(25);
        // stdin events are handled on another thread
        std::thread::spawn(move || {
            let mut buf = [0; 1000];
            loop {
                let mut lock = std::io::stdin().lock();
                match lock.read(&mut buf) {
                    Ok(n) => match stdin_sender.blocking_send(buf[0..n].to_vec()) {
                        Ok(()) => continue,
                        Err(_) => return,
                    },
                    Err(_) => return,
                };
            }
        });
        let mut stdout = tokio::io::stdout();
        let mut stdin_closed = false;

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
                r = stdin.recv(), if !stdin_closed => {
                    match r {
                        None => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Some(buf) => {
                            // Ctrl+Q pressed, escape all further output until esc is pressed
                            if buf.contains(&17u8) {
                            }
                            channel.data(buf.as_slice()).await?;
                        },
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
