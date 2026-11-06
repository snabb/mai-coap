//! Host EDHOC client. Arguments: remote own.ccs private.raw peer.ccs combined path [payload|observe].
mod support;
use mai_coap::{
    codec::{Code, OptionNumber},
    crypto::SoftwareCrypto,
    edhoc::endpoint::Edhoc,
    endpoint::{DefaultEndpoint, DefaultShared, Request, ResponseWriter},
    security::{PeerId, ProtectedOnly},
    time::StdClock,
    transport::linux::StdTransport,
};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 7 {
        return Err("usage: secured-client REMOTE OWN_CCS PRIVATE_RAW PEER_CCS COMBINED PATH [PAYLOAD|observe]".into());
    }
    let (identity, peer) = support::credentials(&args[2], &args[3], &args[4])?;
    let remote: core::net::SocketAddr = args[1].parse()?;
    let mut protection = Edhoc::<_>::new(SoftwareCrypto::new(rand::rng()), identity)?;
    protection.trust(peer)?;
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut socket = StdTransport::bind(bind.parse()?)?;
    let shared = DefaultShared::new();
    let mut endpoint = DefaultEndpoint::new(&shared, protection)?;
    let clock = StdClock::default();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_>| Err(Code::NOT_FOUND);
    let driver = endpoint.run(&mut socket, &clock, &mut app, &ProtectedOnly);
    let work = async {
        let mut client = shared
            .handle()
            .client(remote)
            .peer(PeerId(1))
            .combined_edhoc(args[5].parse().map_err(|_| mai_coap::Error::Malformed)?);
        if args[6].starts_with("coap://") {
            client = client.through_proxy();
        }
        if args.get(7).is_some_and(|arg| arg == "observe") {
            let mut observation = client.observe(&args[6])?;
            for _ in 0..3 {
                let reply = observation
                    .next()
                    .await
                    .ok_or(mai_coap::Error::Cancelled)??;
                println!("{}", String::from_utf8_lossy(reply.message()?.payload()));
            }
            observation.cancel();
        } else if let Some(payload) = args.get(7) {
            let operation = client
                .request(Code::POST, &args[6])?
                .uint_option(OptionNumber::CONTENT_FORMAT, 0)?
                .payload(payload.as_bytes())?
                .send()?;
            let reply = operation.await?;
            let message = reply.message()?;
            if !message.code().is_success() {
                return Err(mai_coap::Error::Response(message.code()));
            }
            std::io::stdout().write_all(message.payload()).unwrap();
        } else {
            let mut body = [0; 8192];
            let n = client.get_blocks(&args[6], 6, &mut body).await?;
            std::io::stdout().write_all(&body[..n]).unwrap();
        }
        Ok::<_, mai_coap::Error>(())
    };
    futures_lite::future::block_on(futures_lite::future::race(
        async { driver.await.map_err(|e| e.to_string()) },
        async { work.await.map_err(|e| e.to_string()) },
    ))?;
    Ok(())
}
