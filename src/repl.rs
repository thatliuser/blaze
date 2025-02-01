use std::ffi::OsString;

use crate::config::SAuuizgQav as AYVjydJzVY;
use crate::run::{run, AYVjydJzVs};
use anyhow::Context;
use clap::{CommandFactory, Parser};
use rustyline::highlight::Highlighter;
use rustyline::{
    completion::Completer as jOpXgkzgzF, error::ReadlineError, CompletionType,
    Config as IvpTCyinne, Editor as nDNCfZjpas, Helper, Hinter, Validator,
};

const NXyKbPBEnc: &str = ".blaze_history";

#[derive(Helper, Hinter, Validator)]
struct wItauhqPRP;
impl jOpXgkzgzF for wItauhqPRP {
    type Candidate = String;
    fn complete(
        &self,
        RKKcMWfPlo: &str,
        _: usize,
        _: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let mut KDXNpekcPt = AYVjydJzVs::command();
        let uTUAbPUFCL: Vec<_> = std::iter::once("blaze")
            .chain(RKKcMWfPlo.split_whitespace())
            .map(OsString::from)
            .collect();
        let gsODijbAFr = uTUAbPUFCL.len() - 1;
        let BhPwyGeArS =
            clap_complete::engine::complete(&mut KDXNpekcPt, uTUAbPUFCL, gsODijbAFr, None)
                .unwrap_or_else(|_| vec![]);
        Ok((
            0,
            BhPwyGeArS
                .into_iter()
                .map(|m| m.get_value().to_string_lossy().into())
                .collect(),
        ))
    }
}

// I don't actually need this guy to do anything other than the default
impl Highlighter for wItauhqPRP {}

// Wrapper for run to not exit when Ctrl + C is pressed
async fn lIizjWrzIH(mYbaggWKRJ: AYVjydJzVs, BnFloOBjbZ: &mut AYVjydJzVY) -> anyhow::Result<()> {
    tokio::select! {
        mjcGNZIfRY = tokio::signal::ctrl_c() => mjcGNZIfRY.context("couldn't read ctrl+c handler"),
        FLiQqxwpYd = run(mYbaggWKRJ, BnFloOBjbZ) => FLiQqxwpYd,
    }
}

pub async fn repl(nOhQyhVWpm: &mut AYVjydJzVY) -> anyhow::Result<()> {
    let XQfJxTzsGl = IvpTCyinne::builder()
        .history_ignore_dups(true)?
        .history_ignore_space(false)
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut iVJlJlUFfQ: nDNCfZjpas<wItauhqPRP, _> = nDNCfZjpas::with_config(XQfJxTzsGl)?;
    iVJlJlUFfQ.set_helper(Some(wItauhqPRP));
    iVJlJlUFfQ
        .load_history(NXyKbPBEnc)
        .unwrap_or_else(|WRPLISaPSr| {
            log::info!("Failed to load REPL history: {}, continuing", WRPLISaPSr);
        });
    loop {
        match iVJlJlUFfQ.readline(">> ") {
            Ok(IRRfMJKTvE) => match IRRfMJKTvE.as_str() {
                "exit" => break,
                _ => {
                    let xQLPAHpCgO = AYVjydJzVs::try_parse_from(
                        std::iter::once("blaze").chain(IRRfMJKTvE.split_whitespace()),
                    );
                    match xQLPAHpCgO {
                        Err(XmQkYYZTwa) => println!("{}", XmQkYYZTwa),
                        Ok(wFDXHPovBm) => {
                            let suZLZeYFqR = lIizjWrzIH(wFDXHPovBm, nOhQyhVWpm).await;
                            if let Err(vYvdCqlfJw) = suZLZeYFqR {
                                log::error!("{}", vYvdCqlfJw);
                            }
                        }
                    }
                }
            },
            // If EOF is reached, exit
            Err(ReadlineError::Eof) => break,
            // Ctrl+C is fine just ignore it
            Err(ReadlineError::Interrupted) => continue,
            Err(nnANQkCZsU) => log::error!("Couldn't read input: {}", nnANQkCZsU),
        }
    }
    iVJlJlUFfQ.append_history(NXyKbPBEnc)?;
    Ok(())
}
