// Embedded script files.

use std::io;
use std::path::{Path, PathBuf};

#[derive(rust_embed::Embed)]
#[folder = "scripts/"]
pub struct Scripts;

impl Scripts {
    pub fn root() -> PathBuf {
        "scripts/".into()
    }

    // Returns a boolean signaling whether or not the directory already existed
    fn create_dir(path: &Path) -> anyhow::Result<bool> {
        let result = std::fs::create_dir(path);
        if let Err(err) = result {
            if err.kind() == io::ErrorKind::AlreadyExists {
                println!("Directory already exists, skipping unpack step");
                Ok(true)
            } else {
                Err(err.into())
            }
        } else {
            Ok(false)
        }
    }

    // Find a script, either embedded in the executable or in the scripts directory.
    pub async fn find(name: &str) -> Option<Vec<u8>> {
        match Self::get(name) {
            Some(file) => Some(file.data.into()),
            None => {
                let mut path = Self::root();
                path.push(name);
                tokio::fs::read(&path).await.ok()
            }
        }
    }
}
