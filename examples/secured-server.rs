//! Host EDHOC/OSCORE server. Arguments: bind-address own.ccs private.raw peer.ccs.
mod support;
#[cfg(feature = "xarxa-ipv4")]
#[path = "support/xarxa.rs"]
mod xarxa_bridge;
use mai_coap::{
    codec::{Code, ContentFormat},
    crypto::SoftwareCrypto,
    edhoc::endpoint::Edhoc,
    endpoint::{DefaultEndpoint, DefaultShared, Disposition, Request, ResponseWriter},
    observe::Settings,
    security::ProtectedOnly,
    server::{DefaultRouter, SliceBody},
    time::StdClock,
    transport::linux::StdTransport,
};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: secured-server BIND OWN_CCS PRIVATE_RAW PEER_CCS".into());
    }
    let (identity, peer) = support::credentials(&args[2], &args[3], &args[4])?;
    let mut protection = Edhoc::<_>::new(SoftwareCrypto::new(rand::rng()), identity)?;
    protection.trust(peer)?;
    let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
        response.set_payload(b"hello secured")?;
        Ok(Disposition::Complete)
    };
    let mut echo = |request: Request<'_>, response: &mut ResponseWriter<'_>| {
        response.set_code(Code::CHANGED);
        response.set_payload(request.payload())?;
        Ok(Disposition::Complete)
    };
    let mut counter = 0u32;
    let mut observable = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
        counter = counter.wrapping_add(1);
        response.set_payload(counter.to_string().as_bytes())?;
        Ok(Disposition::Complete)
    };
    let body = [b'z'; 3000];
    let mut large = {
        let mut body = SliceBody::new(&body, ContentFormat::TEXT);
        body.etag = b"fixed";
        body.max_age = 60;
        body
    };
    let mut router = DefaultRouter::new(&ProtectedOnly);
    router.route("/hello", &[Code::GET], &mut hello)?;
    router.route("/echo", &[Code::POST], &mut echo)?;
    router.route("/clock", &[Code::GET], &mut observable)?;
    router.observable(
        "/clock",
        Settings::new(1)
            .with_minimum_ms(100)
            .with_maximum_ms(500)
            .with_confirmable_ms(1000),
    )?;
    router.representation("/large", &mut large)?;
    let shared = DefaultShared::new();
    #[cfg(feature = "xarxa-ipv4")]
    if std::env::var_os("MAI_COAP_XARXA").is_some() {
        return xarxa_bridge::serve(
            args[1].parse()?,
            &shared,
            protection,
            &mut router,
            &ProtectedOnly,
        );
    }
    let mut socket = StdTransport::bind(args[1].parse()?)?;
    let mut endpoint = DefaultEndpoint::new(&shared, protection)?;
    println!("LISTEN {}", socket.local_addr()?);
    std::io::stdout().flush()?;
    futures_lite::future::block_on(endpoint.run(
        &mut socket,
        &StdClock::default(),
        &mut router,
        &ProtectedOnly,
    ))?;
    Ok(())
}
