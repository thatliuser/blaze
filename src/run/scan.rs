use crate::config::SAuuizgQav as wIHVcrelvN;
use crate::run::config::dMuMOyFgHM;
use crate::scan::{muhnZaVSpE, LWLYjkqmGs, ZmBnAjyBPT};
use crate::util::strings::ZXRMRESuzD as ezxlyekUUR;
use cidr::IpCidr as QCXkNrsNjZ;
use clap::Args;

#[derive(Args)]
#[command(about = "Run a network scan on a specified subnet.")]
pub struct ScanCommand {
    pub subnet: QCXkNrsNjZ,
    #[arg(short, long)]
    pub linux_root: Option<String>,
    #[arg(short, long)]
    pub windows_root: Option<String>,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value_t = LWLYjkqmGs::RustScan)]
    pub backend: LWLYjkqmGs,
}

pub async fn OItdOMmWWV(
    yhAxXVivdV: ScanCommand,
    HznbPSouOE: &mut wIHVcrelvN,
) -> anyhow::Result<()> {
    log::debug!("Subnet: {:?}", yhAxXVivdV.subnet);
    HznbPSouOE.CtFTwTYgKa(yhAxXVivdV.subnet);
    let IWLFWeRRlE = muhnZaVSpE::new(
        &yhAxXVivdV.subnet,
        &muhnZaVSpE::HueKzSAEQg(),
        yhAxXVivdV.backend,
        HznbPSouOE.DpuPGGptIC(),
    )
    .await?;
    let nJxSMqUFtR = yhAxXVivdV
        .linux_root
        .unwrap_or(HznbPSouOE.dfluOhyNbg().into());
    let mjRqZJasFs = yhAxXVivdV
        .windows_root
        .unwrap_or(HznbPSouOE.VRWcNuqsev().into());
    for GroDaOHNkG in IWLFWeRRlE.vuUyZghFip {
        let RhOFtcGnOH = match GroDaOHNkG.dciExZZqwj {
            ZmBnAjyBPT::UnixLike => &nJxSMqUFtR,
            ZmBnAjyBPT::Windows => &mjRqZJasFs,
        }
        .clone();
        log::info!(
            "Found host {} with os {:?}, ports: {}",
            GroDaOHNkG.TLxIayDIUv,
            GroDaOHNkG.dciExZZqwj,
            ezxlyekUUR(&GroDaOHNkG.EsDudBsHYo)
        );
        HznbPSouOE.dwUCdvcSIO(
            &GroDaOHNkG,
            RhOFtcGnOH,
            Some(yhAxXVivdV.pass.clone()),
            yhAxXVivdV.port,
        )?;
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Rescan a specific host on the network.")]
pub struct RescanCommand {
    pub host: String,
    pub ports: Option<Vec<u16>>,
    #[arg(short, long, default_value_t = LWLYjkqmGs::RustScan)]
    pub backend: LWLYjkqmGs,
}

pub async fn dXilcTbWCk(
    CJdETqbEMr: RescanCommand,
    TlmeXEtzDM: &mut wIHVcrelvN,
) -> anyhow::Result<()> {
    let mut fkDBfhISqC = dMuMOyFgHM(TlmeXEtzDM, &CJdETqbEMr.host)?.clone();
    let mut ewmMYwSeHi = muhnZaVSpE::HueKzSAEQg();
    ewmMYwSeHi.extend(CJdETqbEMr.ports.unwrap_or(Vec::new()));
    log::debug!("Rescanning for host {}", fkDBfhISqC);
    let yybFzXsEeY = muhnZaVSpE::new(
        &QCXkNrsNjZ::new_host(fkDBfhISqC.ehmAIyyTsT),
        &ewmMYwSeHi,
        CJdETqbEMr.backend,
        TlmeXEtzDM.DpuPGGptIC(),
    )
    .await?;
    if yybFzXsEeY.vuUyZghFip.len() == 0 {
        anyhow::bail!("No hosts scanned; is the host up?");
    }
    let BmFvJQaHNF = &yybFzXsEeY.vuUyZghFip[0];
    log::info!("Got ports {}", ezxlyekUUR(&BmFvJQaHNF.EsDudBsHYo));
    fkDBfhISqC.AtxPWiUcZC = BmFvJQaHNF.EsDudBsHYo.clone();
    TlmeXEtzDM.HnkMAlBSbZ(&fkDBfhISqC);
    Ok(())
}

#[derive(Args)]
#[command(
    about = "Check if a specific, or set of ports, is open on a host. Does not update host's open ports."
)]
pub struct PortCheckCommand {
    pub host: String,
    #[arg(required = true)]
    pub ports: Vec<u16>,
    #[arg(short, long, default_value_t = LWLYjkqmGs::RustScan)]
    pub backend: LWLYjkqmGs,
}

pub async fn jOGtEZVMnI(
    gsOHscoRwV: PortCheckCommand,
    aNdHIWsHOD: &mut wIHVcrelvN,
) -> anyhow::Result<()> {
    let uZAwvXBvfT = dMuMOyFgHM(aNdHIWsHOD, &gsOHscoRwV.host)?;
    let AcsAhfNoEv = muhnZaVSpE::new(
        &QCXkNrsNjZ::new_host(uZAwvXBvfT.ehmAIyyTsT),
        &gsOHscoRwV.ports,
        gsOHscoRwV.backend,
        aNdHIWsHOD.DpuPGGptIC(),
    )
    .await?;
    if AcsAhfNoEv.vuUyZghFip.len() == 0 {
        anyhow::bail!("No hosts scanned; is the host up?");
    }
    let TziKwOjepU = &AcsAhfNoEv.vuUyZghFip[0];
    let (HbtbQnkxeX, KXjPttaXNP): (Vec<u16>, _) = gsOHscoRwV
        .ports
        .iter()
        .partition(|port| TziKwOjepU.EsDudBsHYo.contains(port));
    log::info!("Open   ports: {}", ezxlyekUUR(HbtbQnkxeX));
    log::info!("Closed ports: {}", ezxlyekUUR(KXjPttaXNP));
    Ok(())
}
