// Embedded script files.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io;

use anyhow::Context;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "scripts/"]
pub struct Scripts;

impl Scripts {
    pub fn root() -> PathBuf {
        "scripts/".into()
    }

    // Returns a boolean signaling whether or not the directory already existed
    async fn create_dir(path: &Path) -> anyhow::Result<bool> {
        let result = tokio::fs::create_dir(path).await;
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

    async fn copy_file(file: &str) -> anyhow::Result<()> {
        let contents = Self::get(file).with_context(|| format!("failed to open file {}", file))?;
        let mut path = Self::root();
        path.push(file);
        let mut dst = File::create(path).await?;
        let mut src = Cursor::new(contents.data);
        io::copy(&mut src, &mut dst).await?;
        Ok(())
    }

    pub async fn unpack() -> anyhow::Result<()> {
        let root = Self::root();
        let existed = Self::create_dir(&root).await?;
        if !existed {
            for file in Self::iter() {
                if let Err(err) = Self::copy_file(&file).await {
                    println!("Failed to copy file {}: {}", file, err);
                }
            }
        }
        Ok(())
    }

    // Find a script, either embedded in the executable or in the scripts directory.
    pub async fn find(file: &Path) -> Option<File> {
        let mut path = Self::root();
        path.push(file);
        File::open(path).await.ok()
    }
}
