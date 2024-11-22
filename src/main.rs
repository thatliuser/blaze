use clap::Parser;
use std::io::{Read, Write};
use tokio::{join, task};
use wezterm_ssh::{Child, Config, MasterPty, PtySize, Session, SessionEvent};

#[derive(Debug, Parser)]
struct Args {
    pub user: String,
    pub pass: String,
    pub host: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut cfg = Config::new();
    cfg.add_default_config_files();

    let mut cfg = cfg.for_host(args.host);
    cfg.insert("user".to_string(), args.user);

    let task = task::spawn(async move {
        let (sess, events) = Session::connect(cfg.clone()).unwrap();

        while let Ok(ev) = events.recv().await {
            match ev {
                SessionEvent::Banner(banner) => {
                    if let Some(banner) = banner {
                        println!("{}", banner);
                    }
                }
                SessionEvent::HostVerify(verify) => {
                    verify.answer(true).await.unwrap();
                }
                SessionEvent::Authenticate(auth) => {
                    auth.answer(vec![args.pass.clone()]).await.unwrap();
                }
                SessionEvent::Error(err) => {
                    panic!("{}", err);
                }
                SessionEvent::Authenticated => break,
            }
        }

        let (pty, mut child) = sess
            .request_pty("xterm-256color", PtySize::default(), Some("ls -lA"), None)
            .await
            .unwrap();

        let mut reader = pty.try_clone_reader().unwrap();
        let stdout = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut stdout = std::io::stdout();
            while let Ok(len) = reader.read(&mut buf) {
                if len == 0 {
                    break;
                }
                if stdout.write_all(&buf[0..len]).is_err() {
                    break;
                }
            }
        });

        // Need to separate out the writer so that we can drop
        // the pty which would otherwise keep the ssh session
        // thread alive
        let mut writer = pty.try_clone_writer().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut stdin = std::io::stdin();
            while let Ok(len) = stdin.read(&mut buf) {
                if len == 0 {
                    break;
                }
                if writer.write_all(&buf[0..len]).is_err() {
                    break;
                }
            }
        });

        let status = child.wait().unwrap();
        let _ = stdout.join();
        if !status.success() {
            std::process::exit(1);
        }
    });
    join!(task);
}
