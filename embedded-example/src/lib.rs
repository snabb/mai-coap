//! Board-independent Embassy task body. The board supplies the running network
//! stack, its critical-section implementation, timer driver and secure RNG.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(any(feature = "xarxa", feature = "embassy-xarxa"))]
pub mod xarxa;

use mai_coap::{
    codec::Code,
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    security::PublicPaths,
    server::Router,
    time::EmbassyClock,
    transport::embassy::EmbassyTransport,
};

/// Serves one explicitly public resource on the application's Embassy stack.
/// The board executor owns and polls this future alongside its network runner.
pub async fn serve(
    stack: embassy_net::Stack<'_>,
    rng: impl rand_core::CryptoRng,
) -> Result<(), &'static str> {
    let mut receive_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 2];
    let mut transmit_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 2];
    let mut receive = [0; 1536];
    let mut transmit = [0; 1536];
    let mut socket = embassy_net::udp::UdpSocket::new(
        stack,
        &mut receive_metadata,
        &mut receive,
        &mut transmit_metadata,
        &mut transmit,
    );
    socket.bind(5683).map_err(|_| "UDP bind failed")?;
    let mut transport = EmbassyTransport { socket };
    let shared = Shared::<768, 4>::new();
    let mut endpoint =
        Endpoint::<_, 768, 4, 8>::new(&shared, Unsecured(rng)).map_err(|_| "endpoint capacity")?;
    let policy = PublicPaths(&[(Code::GET, "/hello")]);
    let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_, 768>| {
        response
            .set_payload(b"hello from Embassy")
            .map_err(|_| Code::INTERNAL_ERROR)?;
        Ok(Disposition::Complete)
    };
    let mut router = Router::<768, 1>::new(&policy);
    router
        .route("/hello", &[Code::GET], &mut hello)
        .map_err(|_| "route capacity")?;
    endpoint
        .run(&mut transport, &EmbassyClock, &mut router, &policy)
        .await
        .map_err(|_| "endpoint driver failed")
}
