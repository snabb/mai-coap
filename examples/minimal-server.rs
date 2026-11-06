//! Minimal host server; public paths are an explicit application policy choice.
use mai_coap::{
    codec::Code,
    endpoint::{DefaultEndpoint, DefaultShared, Disposition, Request, ResponseWriter, Unsecured},
    security::PublicPaths,
    server::DefaultRouter,
    time::StdClock,
    transport::linux::StdTransport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_lite::future::block_on(async {
        let address = std::env::args()
            .nth(1)
            .unwrap_or("127.0.0.1:5683".into())
            .parse()?;
        let mut socket = StdTransport::bind(address)?;
        let policy = PublicPaths(&[(Code::GET, "/hello"), (Code::POST, "/echo")]);
        let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_payload(b"hello")?;
            Ok(Disposition::Complete)
        };
        let mut echo = |request: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_code(Code::CHANGED);
            response.set_payload(request.payload())?;
            Ok(Disposition::Complete)
        };
        let mut resources = DefaultRouter::new(&policy);
        resources.route("/hello", &[Code::GET], &mut hello)?;
        resources.route("/echo", &[Code::POST], &mut echo)?;
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
        println!("listening on {}", socket.local_addr()?);
        resources
            .run(&mut endpoint, &mut socket, &StdClock::default())
            .await?;
        Ok(())
    })
}
