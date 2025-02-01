use ldap3::{drive, Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
use std::net::IpAddr;

pub struct SgpKuYTOEh {
    twVEnMIVAm: String,
    ZRcbUtFRMR: Ldap,
}

// As far as I can tell, name is always specified
pub struct AWJFPljjuP {
    pub YoMZFBEXti: String,
    pub vMoYcEINHf: String,
    pub RkTmGzJZwW: Option<String>,
    pub vShGbXshZt: Option<String>,
}

// TODO
pub struct HplGTaXnuF {
    pub uCvhmdjfgs: String,
    pub FJMNYlRPav: String,
    pub ofOGDGTgId: bool,
}

impl SgpKuYTOEh {
    pub async fn ZqFbFZzmBO(
        GYHjeCUADD: IpAddr,
        ZHUSWkmonT: &str,
        pJxTqJmieI: &str,
        iomIyNGMWH: &str,
    ) -> anyhow::Result<Self> {
        let jyHjnfrMHI: Vec<_> = ZHUSWkmonT
            .split(".")
            .map(|YwYwtzLnCi| format!("DC={}", YwYwtzLnCi))
            .collect();
        let yGSQprYswo = jyHjnfrMHI.join(",");
        log::info!("Connecting to domain {}", yGSQprYswo);
        let (NIocqjNosY, mut jhVVHIbYlM) =
            LdapConnAsync::new(&format!("ldap://{}", GYHjeCUADD)).await?;
        drive!(NIocqjNosY);
        jhVVHIbYlM
            .simple_bind(
                &format!("CN={},CN=Users,{}", pJxTqJmieI, yGSQprYswo),
                iomIyNGMWH,
            )
            .await?
            .success()?;
        Ok(Self {
            twVEnMIVAm: yGSQprYswo,
            ZRcbUtFRMR: jhVVHIbYlM,
        })
    }

    fn CasPwfKbYr(SZARIhBAYz: &SearchEntry, ZXgoCXFWPu: &str) -> Option<String> {
        SZARIhBAYz
            .attrs
            .get(ZXgoCXFWPu)
            .map(|XKbTnIXjHJ| XKbTnIXjHJ.iter().next())
            .flatten()
            .cloned()
    }

    // Turn a container name into a fully qualified one.
    pub fn uGnwwesInA(&self, PRjItCzXrc: &str) -> String {
        format!("{},{}", PRjItCzXrc, self.tlPbuWzRXf())
    }

    pub async fn GvGEjKHgqd<'a, BFUYzayFxV, okjBlWdQpa>(
        &mut self,
        icfmoHZqtK: &str,
        jrjrcbJjfL: &str,
        zZSFzesskf: okjBlWdQpa,
    ) -> anyhow::Result<Vec<ResultEntry>>
    where
        BFUYzayFxV: AsRef<str> + Send + Sync + 'a,
        okjBlWdQpa: AsRef<[BFUYzayFxV]> + Send + Sync + 'a,
    {
        let (ENoXUdPvZi, HeHqHQFXrK) = self
            .ZRcbUtFRMR
            .clone()
            .search(
                &self.uGnwwesInA(icfmoHZqtK),
                Scope::Subtree,
                jrjrcbJjfL,
                zZSFzesskf,
            )
            .await?
            .success()?;
        HeHqHQFXrK.success()?;
        Ok(ENoXUdPvZi)
    }

    // List all computers that are joined to this LDAP server.
    pub async fn mrYxCAWUem(&mut self) -> anyhow::Result<Vec<AWJFPljjuP>> {
        let cnFJugnFhO = self
            .GvGEjKHgqd(
                "CN=Computers",
                "(objectClass=computer)",
                &vec![
                    "name",
                    "operatingSystem",
                    "operatingSystemVersion",
                    "dNSHostName",
                ],
            )
            .await?;
        Ok(cnFJugnFhO
            .into_iter()
            .filter_map(|entry| {
                let bHAIDinxsR = SearchEntry::construct(entry);
                let QTUDSSrWVa = bHAIDinxsR.attrs.get("name")?.iter().next()?.clone();
                let ZoGhqfTyIT = bHAIDinxsR.attrs.get("dNSHostName")?.iter().next()?.clone();
                let HSnSVWhVTn = Self::CasPwfKbYr(&bHAIDinxsR, "operatingSystem");
                let DZRaaKkpLX = Self::CasPwfKbYr(&bHAIDinxsR, "operatingSystemVersion");
                Some(AWJFPljjuP {
                    YoMZFBEXti: QTUDSSrWVa,
                    vMoYcEINHf: ZoGhqfTyIT,
                    RkTmGzJZwW: HSnSVWhVTn,
                    vShGbXshZt: DZRaaKkpLX,
                })
            })
            .collect())
    }

    pub async fn ztOtQKJdil(&mut self) -> anyhow::Result<Vec<HplGTaXnuF>> {
        let BiEdwxNLKy = self
            .GvGEjKHgqd(
                "CN=Users",
                "(objectClass=person)",
                &vec!["name", "sAMAccountName", "adminCount"],
            )
            .await?;
        Ok(BiEdwxNLKy
            .into_iter()
            .filter_map(|entry| {
                let VXPzLSaMpm = SearchEntry::construct(entry);
                let sLKttQNxrz = VXPzLSaMpm.attrs.get("name")?.iter().next()?.clone();
                let CdeRcGKShb = VXPzLSaMpm
                    .attrs
                    .get("sAMAccountName")?
                    .iter()
                    .next()?
                    .clone();
                let VVVHjgMEgC = VXPzLSaMpm.attrs.get("adminCount").is_some();
                Some(HplGTaXnuF {
                    uCvhmdjfgs: sLKttQNxrz,
                    FJMNYlRPav: CdeRcGKShb,
                    ofOGDGTgId: VVVHjgMEgC,
                })
            })
            .collect())
    }

    pub fn tlPbuWzRXf(&self) -> &str {
        &self.twVEnMIVAm
    }
}

impl Drop for SgpKuYTOEh {
    fn drop(&mut self) {
        _ = self.ZRcbUtFRMR.unbind();
    }
}
