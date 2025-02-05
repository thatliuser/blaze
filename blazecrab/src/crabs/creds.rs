use std::path::Path;

use crate::crabs::{Crab, CrabResult};
use regex_automata::meta::Regex;
use serde::Serialize;
use walkdir::{IntoIter, WalkDir};

pub struct CredentialsCrab {}

impl CredentialsCrab {
    fn scan_file(&self, path: &Path) -> anyhow::Result<()> {
        let contents = std::fs::read_to_string(path)?;
        // Regex::new_many()
        todo!()
    }
}

impl Crab for CredentialsCrab {
    fn run(&self) -> CrabResult {
        let dir = WalkDir::new("/");
        // TODO: Transcribe
        let mysql = PatternGroup::new("MySQL Connection Strings", vec![]);
        // TODO: Transcribe 2
        let postgres = PatternGroup::new("PostgreSQL Connection Strings", vec![]);
        for entry in dir.into_iter() {
            if let Ok(entry) = entry {
                let path = entry.path().to_string_lossy();
                if path.contains("/vendor/")
                    || path.contains("/node_modules/")
                    || path.contains("/.git/")
                {
                    // TODO: Finish
                    _ = self.scan_file(entry.path())
                }
            }
        }
        todo!()
    }
    fn priority(&self) -> u64 {
        85
    }
}

pub struct PatternGroup {}

impl PatternGroup {
    fn new(desc: impl Into<String>, patterns: impl IntoIterator<Item = String>) -> Self {
        todo!()
    }
}

#[derive(Serialize)]
pub struct CredentialsCrabResult {
    pub findings: (),
}

#[derive(Clone, Debug)]
pub struct DatabaseCredential {}
