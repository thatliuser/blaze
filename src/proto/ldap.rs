use ldap3::{drive, Ldap, LdapConnAsync, Scope, SearchEntry};
use std::net::IpAddr;

pub struct Session {
    domain: String,
    handle: Ldap,
}

// As far as I can tell, name is always specified
pub struct Computer {
    pub name: String,
    pub dns_name: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
}

// TODO
pub struct User {}

impl Session {
    pub async fn new(ip: IpAddr, domain: &str, pass: &str) -> anyhow::Result<Self> {
        let dcs: Vec<_> = domain.split(".").map(|dc| format!("DC={}", dc)).collect();
        let domain = dcs.join(",");
        log::info!("Connecting to domain {}", domain);
        let (conn, mut handle) = LdapConnAsync::new(&format!("ldap://{}", ip)).await?;
        drive!(conn);
        handle
            .simple_bind(&format!("CN=Administrator,CN=Users,{}", domain), pass)
            .await?
            .success()?;
        Ok(Self { domain, handle })
    }

    fn get_first_attr(entry: &SearchEntry, key: &str) -> Option<String> {
        entry
            .attrs
            .get(key)
            .map(|vec| vec.iter().next())
            .flatten()
            .cloned()
    }

    // List all computers that are joined to this LDAP server.
    pub async fn computers(&mut self) -> anyhow::Result<Vec<Computer>> {
        let (entries, result) = self
            .handle
            .clone()
            .search(
                &format!("CN=Computers,{}", self.domain),
                Scope::Subtree,
                "(objectClass=computer)",
                vec![
                    "name",
                    "operatingSystem",
                    "operatingSystemVersion",
                    "dNSHostName",
                ],
            )
            .await?
            .success()?;
        result.success()?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| {
                let entry = SearchEntry::construct(entry);
                let name = entry.attrs.get("name")?.iter().next()?.clone();
                let dns_name = entry.attrs.get("dNSHostName")?.iter().next()?.clone();
                let os = Self::get_first_attr(&entry, "operatingSystem");
                let os_version = Self::get_first_attr(&entry, "operatingSystemVersion");
                Some(Computer {
                    name,
                    dns_name,
                    os,
                    os_version,
                })
            })
            .collect())
    }

    pub async fn users(&mut self) -> anyhow::Result<Vec<User>> {
        todo!()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        _ = self.handle.unbind();
    }
}
