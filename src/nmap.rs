use serde_xml_rs::from_str;
use std::{fs::read_to_string, process::Command};

enum HostOs {
    UnixLike,
    Windows,
}

struct Host {
    ports: Vec<u16>,
    os: HostOs,
}

fn scan(subnet: impl Into<String>, args: Vec<&str>) -> Option<Vec<Host>> {
    let mut final_args = vec!["--min-rate", "3000"];
    final_args.extend(args);
    final_args.extend(vec!["-oX", "scan.xml", subnet.into().leak()]);
    let result = Command::new("nmap")
        .args(final_args)
        .status()
        .expect("nmap failed to spawn")
        .success();

    if result == false {
        panic!("nmap failed to execute");
    }

    let file = read_to_string("scan.xml").expect("nmap output file not readable");

    None
}

fn scan_fast(subnet: impl Into<String>) -> Option<Vec<Host>> {
    scan(subnet, vec!["-p", "22,88,135,389,445,3389,5985"])
}

fn scan_slow(subnet: impl Into<String>) -> Option<Vec<Host>> {
    // TODO
    scan(subnet, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_fast() {
        scan_fast("10.100.3.0/24");
    }
}
