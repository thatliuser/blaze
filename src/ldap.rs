use ldap3::{drive, LdapConnAsync, Scope, SearchEntry};
use std::net::IpAddr;

pub async fn list_computers(ip: IpAddr, domain: &str, pass: &str) -> anyhow::Result<()> {
    // Convert example.domain.name into DC=example,DC=domain,DC=name
    let dcs: Vec<_> = domain.split(".").map(|dc| format!("DC={}", dc)).collect();
    let domain = dcs.join(",");
    println!("{}", domain);
    let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://{}", ip)).await?;
    drive!(conn);
    ldap.simple_bind(&format!("CN=Administrator,CN=Users,{}", domain), pass)
        .await?
        .success()?;
    let (entries, res) = ldap
        .search(
            &format!("CN=Computers,{}", domain),
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
    res.success()?;
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        let name = entry.attrs.get("name");
        let os = entry.attrs.get("operatingSystem");
        println!("{:?} os: {:?}", name, os);
    }
    ldap.unbind().await?;
    Ok(())
}
