//! Forward proxy with an explicit destination allowlist resolved before startup.
use mai_coap::{
    codec::Code,
    endpoint::{DefaultEndpoint, DefaultShared, Request, ResponseWriter, Unsecured},
    proxy::{ForwardProxy, Routing},
    security::ProtectedOnly,
    time::StdClock,
    transport::linux::StdTransport,
};
use std::{
    io::Write,
    net::{SocketAddr, ToSocketAddrs},
};

struct Destination {
    host: String,
    port: u16,
    remote: SocketAddr,
}
impl Routing for Destination {
    fn allow(&self, _: SocketAddr, host: &str, port: u16) -> bool {
        port == self.port && (host == self.host || host == self.remote.ip().to_string())
    }
    fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.allow(self.remote, host, port).then_some(self.remote)
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: proxy BIND coap://ALLOWED_HOST:PORT".into());
    }
    let uri = mai_coap::uri::Uri::parse(&args[2])?;
    let remote = (uri.host, uri.port)
        .to_socket_addrs()?
        .find(SocketAddr::is_ipv4)
        .ok_or("no IPv4 destination")?;
    let destination = Destination {
        host: uri.host.into(),
        port: uri.port,
        remote,
    };
    let mut socket = StdTransport::bind(args[1].parse()?)?;
    let shared = DefaultShared::new();
    let local = |_: Request<'_>, _: &mut ResponseWriter<'_>| Err(Code::NOT_FOUND);
    let mut app = ForwardProxy::<_, _>::new(local, destination, shared.handle())?;
    let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
    println!("LISTEN {}", socket.local_addr()?);
    std::io::stdout().flush()?;
    futures_lite::future::block_on(endpoint.run(
        &mut socket,
        &StdClock::default(),
        &mut app,
        &ProtectedOnly,
    ))?;
    Ok(())
}
