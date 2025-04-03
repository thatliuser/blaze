use ldap3::{drive, Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
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
pub struct User {
    pub name: String,
    pub id: String,
    pub admin: bool,
}

impl Session {
    pub async fn new(ip: IpAddr, domain: &str, user: &str, pass: &str) -> anyhow::Result<Self> {
        let dcs: Vec<_> = domain.split(".").map(|dc| format!("DC={}", dc)).collect();
        let domain = dcs.join(",");
        log::info!("Connecting to domain {}", domain);
        let (conn, mut handle) = LdapConnAsync::new(&format!("ldap://{}", ip)).await?;
        drive!(conn);
        handle
            .simple_bind(&format!("CN={},CN=Users,{}", user, domain), pass)
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

    // Turn a container name into a fully qualified one.
    pub fn qualify(&self, container: &str) -> String {
        format!("{},{}", container, self.domain())
    }

    pub async fn search<'a, S, A>(
        &mut self,
        container: &str,
        filter: &str,
        attrs: A,
    ) -> anyhow::Result<Vec<ResultEntry>>
    where
        S: AsRef<str> + Send + Sync + 'a,
        A: AsRef<[S]> + Send + Sync + 'a,
    {
        let (entries, result) = self
            .handle
            .clone()
            .search(&self.qualify(container), Scope::Subtree, filter, attrs)
            .await?
            .success()?;
        result.success()?;
        Ok(entries)
    }

    // List all computers that are joined to this LDAP server.
    pub async fn computers(&mut self) -> anyhow::Result<Vec<Computer>> {
        let entries = self
            .search(
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
        let entries = self
            .search(
                "CN=Users",
                "(objectClass=person)",
                &vec!["name", "sAMAccountName", "adminCount"],
            )
            .await?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| {
                let entry = SearchEntry::construct(entry);
                let name = entry.attrs.get("name")?.iter().next()?.clone();
                let id = entry.attrs.get("sAMAccountName")?.iter().next()?.clone();
                let admin = entry.attrs.get("adminCount").is_some();
                Some(User { name, id, admin })
            })
            .collect())
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        _ = self.handle.unbind();
    }
}
