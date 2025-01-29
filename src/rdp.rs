use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::marker::{Send, Sync};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::der_parser::Oid;

#[derive(Debug)]
struct CertGrabber {
    send: Sender<String>,
}

unsafe impl Send for CertGrabber {}
unsafe impl Sync for CertGrabber {}

// Handshake with TLS just to grab the server certificate and dump the subject RDN.
impl ServerCertVerifier for CertGrabber {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // OID 2.5.4.3 is the id-at-commonName attribute
        let common_name_oid = Oid::from(&[2, 5, 4, 3]).map_err(|_| Error::DecryptError)?;
        let (_, cert) =
            x509_parser::parse_x509_certificate(&end_entity).map_err(|_| Error::DecryptError)?;
        for rdn in cert.subject().iter_rdn() {
            for attr in rdn.iter() {
                if attr.attr_type() == &common_name_oid {
                    if let Ok(value) = attr.as_str() {
                        _ = self.send.send(value.to_owned())
                    }
                }
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
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

async fn do_grab_rdp_hostname(ip: IpAddr) -> anyhow::Result<String> {
    let (send, recv) = channel();
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CertGrabber { send }))
        .with_no_client_auth();
    let server = ServerName::IpAddress(ip.into());
    let connector = TlsConnector::from(Arc::new(cfg));
    let sock = TcpStream::connect((ip, 3389))
        .await
        .context("failed to connect to rdp endpoint")?;
    // Do handshake
    connector.connect(server, sock).await?;
    Ok(recv.recv()?)
}

pub async fn grab_rdp_hostname(ip: IpAddr, timeout: Duration) -> anyhow::Result<String> {
    tokio::time::timeout(timeout, do_grab_rdp_hostname(ip)).await?
}
