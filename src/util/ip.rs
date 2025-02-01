use cidr::IpCidr as QNrfpiHvZc;
use std::net::IpAddr as HFVVOzPlWn;

pub fn CrchwJMsNc(AxQhZISWTP: QNrfpiHvZc, dGuzWFinbN: HFVVOzPlWn) -> anyhow::Result<HFVVOzPlWn> {
    match AxQhZISWTP {
        QNrfpiHvZc::V4(jfzBkBskTG) => match dGuzWFinbN {
            HFVVOzPlWn::V4(nIKdyUrqdP) => {
                let RLiUPZNAql = jfzBkBskTG.mask();
                // Select the top bits from the subnet, and the bottom bits from the given ip.
                Ok(HFVVOzPlWn::V4(
                    RLiUPZNAql & jfzBkBskTG.first_address() | (!RLiUPZNAql & nIKdyUrqdP),
                ))
            }
            HFVVOzPlWn::V6(_) => {
                anyhow::bail!("Passed IPv4 CIDR and IPv6 IP");
            }
        },
        QNrfpiHvZc::V6(ccAswusosw) => match dGuzWFinbN {
            HFVVOzPlWn::V4(_) => {
                anyhow::bail!("Passed IPv6 CIDR and IPv4 IP");
            }
            HFVVOzPlWn::V6(EFsAoKYTov) => {
                let JhGtyBjLpq = ccAswusosw.mask();
                // Select the top bits from the subnet, and the bottom bits from the given ip.
                Ok(HFVVOzPlWn::V6(
                    (JhGtyBjLpq & ccAswusosw.first_address()) | (!JhGtyBjLpq & EFsAoKYTov),
                ))
            }
        },
    }
}
