use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Host;
use crate::scripts::Scripts;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use crossterm::terminal;
use russh::client::{DisconnectReason, Msg};
use russh::*;
use russh_keys::key::PublicKey;
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

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

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        log::trace!("disconected: {:?}", reason);
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(e) => Err(e),
        }
    }
}

/// This struct is a convenience wrapper
/// around a russh client
/// that handles the input/output event loop
pub struct Session {
    session: client::Handle<Handler>,
    sftp: Option<SftpSession>,
    exec: Option<Channel<Msg>>,
}

impl Session {
    pub async fn connect<A: ToSocketAddrs>(
        user: &str,
        pass: &str,
        addrs: A,
    ) -> anyhow::Result<Self> {
        let config = client::Config {
            // Don't want the inactivity to kill the session from our side
            inactivity_timeout: Some(Duration::from_secs(86400)),
            keepalive_interval: Some(Duration::from_secs(10)),
            // Tolerate only 20 seconds of frozen terminal before failing
            keepalive_max: 2,
            ..<_>::default()
        };

        let config = Arc::new(config);
        let handler = Handler {};

        let mut session = client::connect(config, addrs, handler).await?;

        let auth_res = session.authenticate_password(user, pass).await?;
        if !auth_res {
            anyhow::bail!("Authentication (with password) failed");
        }

        Ok(Self {
            session,
            sftp: None,
            exec: None,
        })
    }

    // Read the first line of the server, which prints the ID
    async fn do_read_server_id<A: ToSocketAddrs>(addrs: A) -> anyhow::Result<String> {
        // This should take a really short amount of time because it's just connecting
        let stream = TcpStream::connect(addrs)
            .await
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

    async fn get_sftp_session<'a>(&'a mut self) -> anyhow::Result<&'a mut SftpSession> {
        if self.sftp.is_none() {
            let session = self.session.channel_open_session().await?;
            session
                .request_subsystem(true, "sftp")
                .await
                .context("couldn't request sftp subsystem")?;
            self.sftp = Some(SftpSession::new(session.into_stream()).await?);
        }
        Ok(self.sftp.as_mut().unwrap())
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
        let sftp = self.get_sftp_session().await?;
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
        Ok(filename.into())
    }

    async fn get_exec_channel<'a>(&'a mut self) -> anyhow::Result<&'a mut Channel<Msg>> {
        if self.exec.is_none() {
            self.exec = Some(self.session.channel_open_session().await?);
        }
        Ok(self.exec.as_mut().unwrap())
    }

    pub async fn exec(&mut self, command: String, capture: bool) -> anyhow::Result<(u32, Vec<u8>)> {
        let exec = self.get_exec_channel().await?;
        exec.exec(true, command).await?;
        let mut code = 0;
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            // There's an event available on the session channel
            let Some(msg) = exec.wait().await else {
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

    async fn do_shell(&mut self, channel: &mut Channel<Msg>) -> anyhow::Result<u32> {
        let code;
        let mut stdout = tokio::io::stdout();
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0; 1000];
        let mut stdin_closed = false;

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
                        Ok(n) => {
                            // Ctrl+Q pressed, escape all further output until esc is pressed
                            if buf[..n].contains(&17u8) {
                            }
                            channel.data(&buf[..n]).await?;
                        },
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                msg = channel.wait() => match msg {
                    Some(msg) => match msg {
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
                    },
                    None => anyhow::bail!("Shell prematurely exited"),
                },
            }
        }

        Ok(code)
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

        terminal::enable_raw_mode()?;
        let code = self.do_shell(&mut channel).await;
        terminal::disable_raw_mode()?;

        // I think this renders the channel unusable, not sure though
        _ = channel.close().await;

        code
    }

    pub async fn close(&mut self) -> anyhow::Result<()> {
        if let Some(sftp) = &mut self.sftp {
            sftp.close().await?;
        }
        if let Some(exec) = &mut self.exec {
            exec.close().await?;
        }
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.session.is_closed()
    }
}

pub struct SessionPool {
    sessions: HashMap<IpAddr, Session>,
}

impl SessionPool {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub async fn try_get<'a>(&'a mut self, host: &Host) -> anyhow::Result<&'a Session> {
        let reopen = match self.sessions.get(&host.ip) {
            Some(session) => session.is_closed(),
            None => true,
        };
        if reopen {
            let Some(pass) = &host.pass else {
                anyhow::bail!("No password set for host!");
            };
            let session = Session::connect(&host.user, &pass, (host.ip, host.port)).await?;
            self.sessions.insert(host.ip, session);
        }

        Ok(self.sessions.get(&host.ip).unwrap())
    }
}
