use std::ffi::OsString;

use crate::config::Config as BlazeConfig;
use crate::run::{run, BlazeCommand};
use anyhow::Context;
use clap::{CommandFactory, Parser};
use rustyline::highlight::Highlighter;
use rustyline::{
    completion::Completer, error::ReadlineError, CompletionType, Config, Editor, Helper, Hinter,
    Validator,
};

const HISTORY_FILE: &str = ".blaze_history";

#[derive(Helper, Hinter, Validator)]
struct ClapCompleter;
impl Completer for ClapCompleter {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        _: usize,
        _: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let mut cmd = BlazeCommand::command();
        let args: Vec<_> = std::iter::once("blaze")
            .chain(line.split_whitespace())
            .map(OsString::from)
            .collect();
        let index = args.len() - 1;
        let matches =
            clap_complete::engine::complete(&mut cmd, args, index, None).unwrap_or_else(|_| vec![]);
        Ok((
            0,
            matches
                .into_iter()
                .map(|m| m.get_value().to_string_lossy().into())
                .collect(),
        ))
    }
}

// I don't actually need this guy to do anything other than the default
impl Highlighter for ClapCompleter {}

// Wrapper for run to not exit when Ctrl + C is pressed
async fn do_run(cmd: BlazeCommand, cfg: &mut BlazeConfig) -> anyhow::Result<()> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.context("couldn't read ctrl+c handler"),
        result = run(cmd, cfg) => result,
    }
}

pub async fn repl(cfg: &mut BlazeConfig) -> anyhow::Result<()> {
    let mut cmd = BlazeCommand::command();
    let config = Config::builder()
        .history_ignore_dups(true)?
        .history_ignore_space(false)
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut reader: Editor<ClapCompleter, _> = Editor::with_config(config)?;
    reader.set_helper(Some(ClapCompleter));
    reader.load_history(HISTORY_FILE).unwrap_or_else(|e| {
        log::info!("Failed to load REPL history: {}, continuing", e);
    });
    loop {
        match reader.readline(">> ") {
            Ok(line) => match line.as_str() {
                "help" => {
                    cmd.print_long_help().context("couldn't print help")?;
                }
                "exit" => break,
                _ => {
                    let cmd = BlazeCommand::try_parse_from(
                        std::iter::once("blaze").chain(line.split_whitespace()),
                    );
                    match cmd {
                        Err(err) => println!("{}", err),
                        Ok(cmd) => {
                            let res = do_run(cmd, cfg).await;
                            if let Err(err) = res {
                                log::error!("{}", err);
                            }
                        }
                    }
                }
            },
            // If EOF is reached, exit
            Err(ReadlineError::Eof) => break,
            // Ctrl+C is fine just ignore it
            Err(ReadlineError::Interrupted) => continue,
            Err(err) => log::error!("Couldn't read input: {}", err),
        }
    }
    reader.append_history(HISTORY_FILE)?;
    Ok(())
}
