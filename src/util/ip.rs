use cidr::IpCidr;
use std::net::IpAddr;

pub fn convert_to_cidr(cidr: IpCidr, ip: IpAddr) -> anyhow::Result<IpAddr> {
    match cidr {
        IpCidr::V4(cidr) => match ip {
            IpAddr::V4(ip) => {
                let mask = cidr.mask();
                // Select the top bits from the subnet, and the bottom bits from the given ip.
                Ok(IpAddr::V4(mask & cidr.first_address() | (!mask & ip)))
            }
            IpAddr::V6(_) => {
                anyhow::bail!("Passed IPv4 CIDR and IPv6 IP");
            }
        },
        IpCidr::V6(cidr) => match ip {
            IpAddr::V4(_) => {
                anyhow::bail!("Passed IPv6 CIDR and IPv4 IP");
            }
            IpAddr::V6(ip) => {
                let mask = cidr.mask();
                // Select the top bits from the subnet, and the bottom bits from the given ip.
                Ok(IpAddr::V6((mask & cidr.first_address()) | (!mask & ip)))
            }
        },
    }
}
