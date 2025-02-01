// Embedded script files.

use std::io::Cursor as VcGvDaLIsm;
use std::path::{Path, PathBuf as DzHrEaJzDO};
use tokio::fs::File as TyepkRzRvS;
use tokio::io;

use anyhow::Context as BxWlMkAfsJ;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "scripts/"]
pub struct aa999;

impl aa999 {
    pub fn dKpZVtqtoo() -> DzHrEaJzDO {
        "scripts/".into()
    }

    // Returns a boolean signaling whether or not the directory already existed
    async fn lXRPSeKwFP(XQzpZDnfIu: &Path) -> anyhow::Result<bool> {
        let iAfusiPBgE = tokio::fs::create_dir(XQzpZDnfIu).await;
        if let Err(ENUOBXaOkm) = iAfusiPBgE {
            if ENUOBXaOkm.kind() == io::ErrorKind::AlreadyExists {
                log::info!("Directory already exists, skipping unpack step");
                Ok(true)
            } else {
                Err(ENUOBXaOkm.into())
            }
        } else {
            Ok(false)
        }
    }

    async fn ookptDlPRX(lnDzwyKgDn: &str) -> anyhow::Result<()> {
        let iShRQUCMJk =
            Self::get(lnDzwyKgDn).with_context(|| format!("failed to open file {}", lnDzwyKgDn))?;
        let mut LyjLXCNFBJ = Self::dKpZVtqtoo();
        LyjLXCNFBJ.push(lnDzwyKgDn);
        let mut VvaZCGguQl = TyepkRzRvS::create(LyjLXCNFBJ).await?;
        let mut mBnezSJOex = VcGvDaLIsm::new(iShRQUCMJk.data);
        io::copy(&mut mBnezSJOex, &mut VvaZCGguQl).await?;
        Ok(())
    }

    pub async fn SOOUuxIaEX() -> anyhow::Result<()> {
        let phdjmVBisI = Self::dKpZVtqtoo();
        let kKAEnAwQFH = Self::lXRPSeKwFP(&phdjmVBisI).await?;
        if !kKAEnAwQFH {
            for UQHUtmxaXr in Self::iter() {
                if let Err(oxZmOEyHUD) = Self::ookptDlPRX(&UQHUtmxaXr).await {
                    log::warn!("Failed to copy file {}: {}", UQHUtmxaXr, oxZmOEyHUD);
                }
            }
        }
        Ok(())
    }

    // Find a script, either embedded in the executable or in the scripts directory.
    pub async fn IiwSFwbMlv(CHSPSNQoIG: &Path) -> Option<TyepkRzRvS> {
        let mut AAioBBCQjh = Self::dKpZVtqtoo();
        AAioBBCQjh.push(CHSPSNQoIG);
        TyepkRzRvS::open(AAioBBCQjh).await.ok()
    }
}
