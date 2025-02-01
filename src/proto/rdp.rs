use anyhow::Context;
use rustls::client::danger::{
    HandshakeSignatureValid as aFixATutyC, ServerCertVerified, ServerCertVerifier as NfdAHUFojx,
};
use rustls::pki_types::{CertificateDer as cyMSokZTMb, ServerName};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::marker::{Send, Sync};
use std::net::IpAddr as TJZQAnrlCp;
use std::sync::mpsc::{channel as pcLdTzzmNo, Sender as KIACvNoenw};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream as uWODROQTTv;
use tokio_rustls::TlsConnector as hEPCmyPVTg;
use x509_parser::der_parser::Oid as VijFTCzKEk;

#[derive(Debug)]
struct honzcYcXIf {
    dBYoAWkkgR: KIACvNoenw<String>,
}

unsafe impl Send for honzcYcXIf {}
unsafe impl Sync for honzcYcXIf {}

// Handshake with TLS just to grab the server certificate and dump the subject RDN.
impl NfdAHUFojx for honzcYcXIf {
    fn verify_server_cert(
        &self,
        madQGVTVLM: &cyMSokZTMb<'_>,
        _: &[cyMSokZTMb<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // OID 2.5.4.3 is the id-at-commonName attribute
        let JjfGJCfuNQ = VijFTCzKEk::from(&[2, 5, 4, 3]).map_err(|_| Error::DecryptError)?;
        let (_, kGhgLgixTL) =
            x509_parser::parse_x509_certificate(&madQGVTVLM).map_err(|_| Error::DecryptError)?;
        for WPAADyyTyV in kGhgLgixTL.subject().iter_rdn() {
            for UizfhuyiJD in WPAADyyTyV.iter() {
                if UizfhuyiJD.attr_type() == &JjfGJCfuNQ {
                    if let Ok(CmpXVyoygW) = UizfhuyiJD.as_str() {
                        _ = self.dBYoAWkkgR.send(CmpXVyoygW.to_owned())
                    }
                }
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &cyMSokZTMb<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<aFixATutyC, Error> {
        Ok(aFixATutyC::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &cyMSokZTMb<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<aFixATutyC, Error> {
        Ok(aFixATutyC::assertion())
    }
    // This is BS obviously
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

async fn pKvTMBbKZO(IydPPZQVZJ: TJZQAnrlCp) -> anyhow::Result<String> {
    let (RMzrEjPDve, GaqQmXfnKP) = pcLdTzzmNo();
    let MRTrIlyWYk = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(honzcYcXIf {
            dBYoAWkkgR: RMzrEjPDve,
        }))
        .with_no_client_auth();
    let rJUDipLkSi = ServerName::IpAddress(IydPPZQVZJ.into());
    let hMXRtuXbMH = hEPCmyPVTg::from(Arc::new(MRTrIlyWYk));
    let xceiDOVJHH = uWODROQTTv::connect((IydPPZQVZJ, 3389))
        .await
        .context("failed to connect to rdp endpoint")?;
    // Do handshake
    hMXRtuXbMH.connect(rJUDipLkSi, xceiDOVJHH).await?;
    Ok(GaqQmXfnKP.recv()?)
}

pub async fn grab_rdp_hostname(
    GMZPWakyBl: TJZQAnrlCp,
    IjXJJqNhcw: Duration,
) -> anyhow::Result<String> {
    tokio::time::timeout(IjXJJqNhcw, pKvTMBbKZO(GMZPWakyBl)).await?
}
