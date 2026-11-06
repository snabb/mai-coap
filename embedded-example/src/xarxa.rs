//! Owned-packet servers with one socket bound to one known interface.
//!
//! The board supplies the running network stack, secure RNG and critical-section
//! implementation. Embassy also requires its timer driver. These functions spawn
//! no tasks: the application polls the server alongside its network runner.
//!
//! Provision buffers for driver RX, queued/cached endpoint packets and copying
//! sends. This server can retain two endpoint buffers; copying a cached CON reply
//! needs another transmit buffer. Each buffer must hold the full 1152-byte payload
//! after UDP/IP and driver headroom. A 1536-byte pool buffer is typical for an IP
//! driver; use the selected socket's allocator rather than guessing headroom.

use mai_coap::{
    XarxaStorage,
    codec::Code,
    endpoint::{Disposition, Request, ResponseWriter, ServerEndpoint, ServerShared, Unsecured},
    security::PublicPaths,
    server::Router,
};

/// Serves an explicitly public resource using an application-owned native stack.
///
/// `access` clones must refer to the same stack and schedule its runner. `handle`
/// must identify an unbound socket owned by the application for this future's lifetime.
/// `interface_id` is the board's nonzero ID, also used as its IPv6 scope ID.
#[cfg(feature = "xarxa")]
pub async fn serve_native<'d, A, C>(
    access: A,
    handle: ::xarxa::udp::UdpHandle,
    iface: ::xarxa::iface::IfaceHandle,
    interface_id: u32,
    rng: impl rand_core::CryptoRng,
    clock: &C,
) -> Result<(), &'static str>
where
    A: mai_coap::transport::xarxa::StackAccess<'d> + Clone,
    C: mai_coap::time::Clock,
{
    use mai_coap::transport::xarxa::XarxaTransport;

    access.with_stack(|stack| {
        let mut socket = stack.udp_socket(handle);
        socket
            .bind_to_iface(Some(iface))
            .map_err(|_| "interface bind failed")?;
        socket.bind(5683, 0).map_err(|_| "UDP bind failed")
    })?;
    let mut transport = XarxaTransport::new(access.clone(), handle, iface, interface_id)
        .map_err(|_| "invalid socket configuration")?;
    let storage =
        XarxaStorage::<_, 2>::new(|| access.with_stack(|stack| stack.udp_socket(handle).alloc()));
    let shared = ServerShared::<1152>::new();
    let mut endpoint = ServerEndpoint::<_, 1152, _>::with_storage(&shared, Unsecured(rng), storage)
        .map_err(|_| "endpoint capacity")?;
    let policy = PublicPaths(&[(Code::GET, "/hello")]);
    let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_, 1152>| {
        response
            .set_payload(b"hello from xarxa")
            .map_err(|_| Code::INTERNAL_ERROR)?;
        Ok(Disposition::Complete)
    };
    let mut router = Router::<1152, 1>::new(&policy);
    router
        .route("/hello", &[Code::GET], &mut hello)
        .map_err(|_| "route capacity")?;
    endpoint
        .run_owned(&mut transport, clock, &mut router, &policy)
        .await
        .map_err(|_| "endpoint driver failed")
}

/// Serves an explicitly public resource on xarxa-backed Embassy.
///
/// The board drives the supplied stack's runner. `interface_id` is its nonzero
/// application-visible interface and IPv6 scope ID.
#[cfg(feature = "embassy-xarxa")]
pub async fn serve_embassy(
    stack: embassy_net_xarxa::Stack<'_>,
    iface: embassy_net_xarxa::udp::IfaceHandle,
    interface_id: u32,
    rng: impl rand_core::CryptoRng,
) -> Result<(), &'static str> {
    use mai_coap::{time::EmbassyClock, transport::embassy_xarxa::EmbassyXarxaTransport};

    let mut socket =
        embassy_net_xarxa::udp::UdpSocket::new(stack).map_err(|_| "socket capacity")?;
    socket
        .bind_to_iface(Some(iface))
        .map_err(|_| "interface bind failed")?;
    socket.bind(5683, 0).map_err(|_| "UDP bind failed")?;
    let mut transport = EmbassyXarxaTransport::new(&socket, iface, interface_id)
        .map_err(|_| "invalid socket configuration")?;
    let storage = XarxaStorage::<_, 2>::new(|| socket.try_alloc());
    let shared = ServerShared::<1152>::new();
    let mut endpoint = ServerEndpoint::<_, 1152, _>::with_storage(&shared, Unsecured(rng), storage)
        .map_err(|_| "endpoint capacity")?;
    let policy = PublicPaths(&[(Code::GET, "/hello")]);
    let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_, 1152>| {
        response
            .set_payload(b"hello from xarxa-backed Embassy")
            .map_err(|_| Code::INTERNAL_ERROR)?;
        Ok(Disposition::Complete)
    };
    let mut router = Router::<1152, 1>::new(&policy);
    router
        .route("/hello", &[Code::GET], &mut hello)
        .map_err(|_| "route capacity")?;
    endpoint
        .run_owned(&mut transport, &EmbassyClock, &mut router, &policy)
        .await
        .map_err(|_| "endpoint driver failed")
}
