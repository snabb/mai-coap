//! Host GET through a background endpoint future on the same executor.
use mai_coap::{
    endpoint::{DefaultEndpoint, DefaultShared, Disposition, Request, ResponseWriter, Unsecured},
    security::ProtectedOnly,
    time::StdClock,
    transport::linux::StdTransport,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_lite::future::block_on(async {
        let remote: core::net::SocketAddr = std::env::args()
            .nth(1)
            .unwrap_or("127.0.0.1:5683".into())
            .parse()?;
        let path = std::env::args().nth(2).unwrap_or("/hello".into());
        let mut socket = StdTransport::bind("127.0.0.1:0".parse()?)?;
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
        let mut no_resources =
            |_: Request<'_>, _: &mut ResponseWriter<'_>| Ok(Disposition::Complete);
        let clock = StdClock::default();
        let handle = shared.handle();
        let request = async {
            let response = handle.client(remote).get(&path).await?;
            let message = response.message()?;
            println!("{}", String::from_utf8_lossy(message.payload()));
            if !message.code().is_success() {
                return Err(mai_coap::Error::Response(message.code()).into());
            }
            Ok(())
        };
        futures_lite::future::race(request, async {
            endpoint
                .run(&mut socket, &clock, &mut no_resources, &ProtectedOnly)
                .await?;
            Ok(())
        })
        .await
    })
}
