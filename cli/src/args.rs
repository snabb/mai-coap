//! Command-line flags: libcoap's short forms and aiocoap's long forms, where they agree.
use crate::{exit::Failure, formats};
use clap::{ArgGroup, Parser};
use mai_coap::codec::{Code, OptionNumber};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "mai-coap",
    version,
    about = "curl-like client for CoAP and EDHOC-secured OSCORE",
    after_help = "Exit codes: 0 success, 1 4.xx or 5.xx response, 2 usage or local error, \
                  3 timeout or network failure, 4 security failure, 130 interrupted.",
    group(ArgGroup::new("body").args(["text", "file", "payload"])),
    group(ArgGroup::new("observing").args(["subscribe", "observe"])),
    group(ArgGroup::new("size").args(["block", "payload_initial_szx"])),
    group(ArgGroup::new("family").args(["ipv4", "ipv6"]))
)]
pub struct Args {
    /// coap:// URI to request
    #[arg(required_unless_present = "generate_identity")]
    pub uri: Option<String>,

    /// Method name (get, post, put, delete, fetch, patch, ipatch) or number
    #[arg(short, long, default_value = "get", value_parser = parse_method)]
    pub method: Code,

    /// Payload text, percent-decoded
    #[arg(short = 'e', value_name = "TEXT")]
    pub text: Option<String>,
    /// Read the payload from FILE, or stdin for -
    #[arg(short = 'f', value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// Payload bytes as given, or @FILE, or @- for stdin
    #[arg(long, value_name = "X")]
    pub payload: Option<String>,

    /// Content-Format of the payload: number, MIME type or short name
    #[arg(short = 't', long, value_name = "FORMAT", value_parser = formats::parse)]
    pub content_format: Option<u16>,
    /// Accepted Content-Format: number, MIME type or short name
    #[arg(short = 'A', long, value_name = "FORMAT", value_parser = formats::parse)]
    pub accept: Option<u16>,
    /// Send a non-confirmable request
    #[arg(short = 'N', long)]
    pub non: bool,

    /// Observe the resource for this many seconds
    #[arg(short = 's', value_name = "SECONDS")]
    pub subscribe: Option<u64>,
    /// Observe the resource until interrupted or the server ends it
    #[arg(long)]
    pub observe: bool,

    /// Block size 16 to 1024, optionally starting a retrieval at block number NUM
    #[arg(short = 'b', value_name = "[NUM,]SIZE", value_parser = parse_block)]
    pub block: Option<BlockArgument>,
    /// Block size exponent, 0 (16 bytes) to 6 (1024 bytes)
    #[arg(long, value_name = "SZX", value_parser = clap::value_parser!(u8).range(0..=6))]
    pub payload_initial_szx: Option<u8>,

    /// Send through this forward proxy
    #[arg(short = 'P', long, value_name = "URI")]
    pub proxy: Option<String>,
    /// Add an option: NUMBER,TEXT or NUMBER,0xHEX. Repeatable
    #[arg(short = 'O', value_name = "NUM,TEXT", value_parser = parse_option)]
    pub options: Vec<RawOption>,
    /// Repeat the request this many times, a second apart, under one security context
    #[arg(
        short = 'G',
        value_name = "COUNT",
        default_value_t = 1,
        value_parser = clap::value_parser!(u8).range(1..)
    )]
    pub repeat: u8,

    /// Local address to bind
    #[arg(short = 'a', value_name = "ADDRESS")]
    pub address: Option<std::net::IpAddr>,
    /// Local port to bind
    #[arg(short = 'p', value_name = "PORT")]
    pub port: Option<u16>,
    /// Never send Uri-Host or Uri-Port
    #[arg(short = 'U', long = "no-set-hostname", conflicts_with = "proxy")]
    pub no_authority: bool,
    /// Use IPv4 only
    #[arg(short = '4')]
    pub ipv4: bool,
    /// Use IPv6 only
    #[arg(short = '6')]
    pub ipv6: bool,

    /// Give up on a request after this many seconds, instead of CoAP's retransmission limits
    #[arg(short = 'B', value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: Option<u64>,
    /// Write the response to FILE; - forces stdout, including binary data on a terminal
    #[arg(short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Append a newline to received data
    #[arg(short = 'w')]
    pub newline: bool,
    /// Largest response body to accept, in bytes
    #[arg(long, value_name = "BYTES", default_value_t = 64 * 1024 * 1024)]
    pub max_size: usize,

    /// More diagnostics on stderr: response details, then library logs
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// No status messages on stderr
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Own EDHOC credential (CCS file)
    #[arg(long, value_name = "FILE", requires = "key", requires = "peer")]
    pub identity: Option<PathBuf>,
    /// Own private key (COSE_Key file as from aiocoap-keygen, not readable by others)
    #[arg(long, value_name = "FILE", requires = "identity", requires = "peer")]
    pub key: Option<PathBuf>,
    /// Trusted credential of the server (CCS file)
    #[arg(long, value_name = "FILE", requires = "identity", requires = "key")]
    pub peer: Option<PathBuf>,
    /// Run EDHOC before the first request instead of combining them
    #[arg(long, requires = "identity")]
    pub sequential_edhoc: bool,

    /// Write a new credential to NAME.ccs and private key to NAME.cosekey, then exit
    #[arg(long, value_name = "NAME", conflicts_with = "uri")]
    pub generate_identity: Option<PathBuf>,
    /// Key identifier for --generate-identity in hexadecimal; default is random
    #[arg(long, value_name = "HEX", conflicts_with = "uri",
        requires = "generate_identity", value_parser = |v: &str| parse_hex(v).map(Hex))]
    pub kid: Option<Hex>,
}

/// Bytes given in hexadecimal; a wrapper because clap reads `Vec<u8>` as repeated values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hex(pub Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockArgument {
    pub number: u32,
    pub szx: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOption {
    pub number: OptionNumber,
    pub value: Vec<u8>,
}

impl Args {
    /// Preferred block size exponent, from either spelling of the flag.
    pub fn szx(&self) -> Option<u8> {
        self.block.map(|b| b.szx).or(self.payload_initial_szx)
    }
    pub fn observing(&self) -> bool {
        self.observe || self.subscribe.is_some()
    }
    /// Reads the request body from its source. Runs before any network activity.
    pub fn body(&self) -> Result<Vec<u8>, Failure> {
        if let Some(text) = &self.text {
            let mut bytes = vec![0; text.len()];
            let n = mai_coap::uri::percent_decode(text.as_bytes(), &mut bytes)
                .map_err(|_| Failure::local("-e: invalid percent-encoding"))?;
            bytes.truncate(n);
            return Ok(bytes);
        }
        if let Some(path) = &self.file {
            return read_source(path);
        }
        let Some(payload) = &self.payload else {
            return Ok(Vec::new());
        };
        if let Some(path) = payload.strip_prefix('@') {
            return read_source(path.as_ref());
        }
        // aiocoap converts this from CBOR diagnostic notation; never send other bytes.
        if self.content_format.is_some_and(formats::is_cbor) {
            return Err(Failure::local(
                "--payload: CBOR diagnostic notation is not supported; use @FILE",
            ));
        }
        Ok(payload.clone().into_bytes())
    }
}

fn read_source(path: &std::path::Path) -> Result<Vec<u8>, Failure> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let result = if path.as_os_str() == "-" {
        std::io::stdin().read_to_end(&mut bytes).map(|_| ())
    } else {
        std::fs::read(path).map(|read| bytes = read)
    };
    result.map_err(|e| Failure::local(format!("{}: {e}", path.display())))?;
    Ok(bytes)
}

fn parse_method(value: &str) -> Result<Code, String> {
    let code = match value.to_ascii_lowercase().as_str() {
        "get" => Code::GET,
        "post" => Code::POST,
        "put" => Code::PUT,
        "delete" => Code::DELETE,
        "fetch" => Code::FETCH,
        "patch" => Code::PATCH,
        "ipatch" => Code::IPATCH,
        other => other
            .parse()
            .ok()
            .map(Code)
            .filter(|code| code.is_request())
            .ok_or_else(|| format!("unknown method {value:?}"))?,
    };
    Ok(code)
}

fn parse_block(value: &str) -> Result<BlockArgument, String> {
    let (number, size) = value.split_once(',').unwrap_or(("0", value));
    let number: u32 = number
        .parse()
        .map_err(|_| format!("invalid block number {number:?}"))?;
    if number > 0xfffff {
        return Err(format!("block number {number} exceeds 2^20 - 1"));
    }
    let szx = match size {
        "16" => 0,
        "32" => 1,
        "64" => 2,
        "128" => 3,
        "256" => 4,
        "512" => 5,
        "1024" => 6,
        _ => return Err(format!("block size {size:?} is not 16, 32, ... or 1024")),
    };
    Ok(BlockArgument { number, szx })
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(format!("invalid hexadecimal {value:?}"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| format!("invalid hexadecimal {value:?}"))
        })
        .collect()
}

/// The library or another flag owns these, and a raw copy would corrupt the request.
const MANAGED_OPTIONS: &[OptionNumber] = &[
    OptionNumber::URI_HOST,
    OptionNumber::OBSERVE,
    OptionNumber::URI_PORT,
    OptionNumber::OSCORE,
    OptionNumber::URI_PATH,
    OptionNumber::URI_QUERY,
    OptionNumber::BLOCK2,
    OptionNumber::BLOCK1,
    OptionNumber::SIZE2,
    OptionNumber::PROXY_URI,
    OptionNumber::PROXY_SCHEME,
    OptionNumber::SIZE1,
];

fn parse_option(value: &str) -> Result<RawOption, String> {
    let (number, text) = value
        .split_once(',')
        .ok_or_else(|| format!("{value:?} is not NUMBER,TEXT"))?;
    let number = OptionNumber(
        number
            .parse()
            .map_err(|_| format!("invalid option number {number:?}"))?,
    );
    if MANAGED_OPTIONS.contains(&number) {
        return Err(format!(
            "option {} is managed by mai-coap or another flag",
            number.0
        ));
    }
    let value = match text.strip_prefix("0x") {
        Some(hex) => parse_hex(hex)?,
        None => text.as_bytes().to_vec(),
    };
    Ok(RawOption { number, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(arguments: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("mai-coap").chain(arguments.iter().copied()))
    }

    #[test]
    fn command_definition_is_consistent() {
        Args::command().debug_assert();
    }

    #[test]
    fn libcoap_and_aiocoap_spellings_match() {
        for arguments in [
            &[
                "-m",
                "PUT",
                "-t",
                "json",
                "-A",
                "60",
                "-N",
                "-P",
                "coap://p",
                "coap://h/x",
            ][..],
            &[
                "--method",
                "put",
                "--content-format",
                "application/json",
                "--accept",
                "application/cbor",
                "--non",
                "--proxy",
                "coap://p",
                "coap://h/x",
            ][..],
        ] {
            let args = parse(arguments).unwrap();
            assert_eq!(args.method, Code::PUT);
            assert_eq!(args.content_format, Some(50));
            assert_eq!(args.accept, Some(60));
            assert!(args.non);
            assert_eq!(args.proxy.as_deref(), Some("coap://p"));
        }
    }

    #[test]
    fn methods_accept_names_and_request_numbers_only() {
        assert_eq!(parse_method("iPATCH"), Ok(Code::IPATCH));
        assert_eq!(parse_method("1"), Ok(Code::GET));
        assert_eq!(parse_method("5"), Ok(Code::FETCH));
        assert!(parse_method("69").is_err());
        assert!(parse_method("0").is_err());
        assert!(parse_method("nonsense").is_err());
    }

    #[test]
    fn block_argument_forms() {
        assert_eq!(parse_block("64"), Ok(BlockArgument { number: 0, szx: 2 }));
        assert_eq!(
            parse_block("3,1024"),
            Ok(BlockArgument { number: 3, szx: 6 })
        );
        assert!(parse_block("100").is_err());
        assert!(parse_block("2048").is_err());
        assert!(parse_block("1048576,64").is_err());
    }

    #[test]
    fn raw_options_decode_text_and_hex_and_refuse_managed_numbers() {
        let number = OptionNumber(2048);
        assert_eq!(
            parse_option("2048,abc"),
            Ok(RawOption {
                number,
                value: b"abc".to_vec()
            })
        );
        assert_eq!(
            parse_option("2048,0x00ff"),
            Ok(RawOption {
                number,
                value: vec![0, 255]
            })
        );
        assert_eq!(
            parse_option("2048,"),
            Ok(RawOption {
                number,
                value: Vec::new()
            })
        );
        assert!(parse_option("2048,0xf").is_err());
        assert!(parse_option("x,1").is_err());
        assert!(parse_option("2048").is_err());
        for number in [3, 6, 7, 9, 11, 15, 23, 27, 28, 35, 39, 60] {
            assert!(parse_option(&format!("{number},x")).is_err(), "{number}");
        }
    }

    #[test]
    fn conflicting_and_incomplete_flags_are_usage_errors() {
        for arguments in [
            &["-e", "a", "-f", "b", "coap://h"][..],
            &["-e", "a", "--payload", "b", "coap://h"],
            &["-s", "1", "--observe", "coap://h"],
            &["-b", "64", "--payload-initial-szx", "2", "coap://h"],
            &["-4", "-6", "coap://h"],
            &["-U", "-P", "coap://p", "coap://h"],
            &["-v", "-q", "coap://h"],
            &["--identity", "a", "coap://h"],
            &["--key", "a", "--peer", "b", "coap://h"],
            &["--sequential-edhoc", "coap://h"],
            &["--kid", "01", "coap://h"],
            &["--generate-identity", "a", "coap://h"],
            &["-G", "0", "coap://h"],
            &["-B", "0", "coap://h"],
            &["--payload-initial-szx", "7", "coap://h"],
            &[],
        ] {
            assert!(parse(arguments).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn verbosity_counts_and_help_is_lowercase_h() {
        assert_eq!(parse(&["-vv", "coap://h"]).unwrap().verbose, 2);
        assert_eq!(
            parse(&["-h"]).unwrap_err().kind(),
            clap::error::ErrorKind::DisplayHelp
        );
    }

    fn body_of(arguments: &[&str]) -> Result<Vec<u8>, Failure> {
        parse(arguments).unwrap().body()
    }

    #[test]
    fn text_is_percent_decoded_but_payload_is_literal() {
        assert_eq!(body_of(&["-e", "a%20b", "coap://h"]).unwrap(), b"a b");
        assert!(body_of(&["-e", "%zz", "coap://h"]).is_err());
        assert_eq!(
            body_of(&["--payload", "a%20b", "coap://h"]).unwrap(),
            b"a%20b"
        );
        assert!(body_of(&["coap://h"]).unwrap().is_empty());
    }

    #[test]
    fn cbor_payload_text_is_refused_rather_than_sent_differently() {
        let error = body_of(&["--payload", "{1:2}", "-t", "cbor", "coap://h"]).unwrap_err();
        assert_eq!(error.code, crate::exit::LOCAL);
        assert_eq!(
            body_of(&["--payload", "{}", "-t", "json", "coap://h"]).unwrap(),
            b"{}"
        );
    }
}
