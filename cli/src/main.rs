//! `mai-coap`: a curl-like command-line client for CoAP and EDHOC-secured OSCORE.
mod args;
mod credentials;
mod exit;
mod formats;
mod output;
mod run;
mod target;

use args::Args;
use clap::Parser;
use exit::Failure;
use mai_coap::{crypto::SoftwareCrypto, edhoc::endpoint::Edhoc, endpoint::Unsecured};
use std::{io::Write, process::ExitCode};

/// Library logs on stderr for `-vv`. The library keeps secrets out of its records.
struct StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        // A closed stderr must not panic the driver, which calls this.
        let _ = writeln!(std::io::stderr(), "{}: {}", record.level(), record.args());
    }
    fn flush(&self) {}
}
static LOGGER: StderrLogger = StderrLogger;

fn run(args: &Args) -> Result<u8, Failure> {
    if args.verbose > 1 {
        let level = if args.verbose > 2 {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Debug
        };
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(level);
        }
    }
    if let Some(name) = &args.generate_identity {
        let (ccs, key) =
            credentials::generate(name, args.kid.as_ref().map(|kid| kid.0.as_slice()))?;
        println!("{}\n{}", ccs.display(), key.display());
        return Ok(exit::SUCCESS);
    }
    let body = args.body()?;
    let route = target::route(args)?;
    let secured = args.identity.is_some();
    let plan = run::Plan {
        args,
        route,
        body,
        secured,
    };
    match (&args.identity, &args.key, &args.peer) {
        (Some(identity), Some(key), Some(peer)) => {
            let mut crypto = SoftwareCrypto::new(rand::rng());
            let (identity, peer) = credentials::load(identity, key, peer, &mut crypto)?;
            let mut protection = Edhoc::<_>::new(crypto, identity)?;
            protection.trust(peer)?;
            // This endpoint only initiates; it has no resources to offer a peer.
            protection.set_responder_limit(0)?;
            run::execute(&plan, protection)
        }
        _ => run::execute(&plan, Unsecured(rand::rng())),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            if !args.quiet {
                exit::report(format!("mai-coap: {}", failure.message));
            }
            ExitCode::from(failure.code)
        }
    }
}
