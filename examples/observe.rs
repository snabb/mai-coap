//! Self-contained host observation; the driver and caller are independent futures.
use futures_lite::future::race;
use mai_coap::{
    codec::Code,
    endpoint::{DefaultEndpoint, DefaultShared, Disposition, Request, ResponseWriter, Unsecured},
    observe::Settings,
    security::PublicPaths,
    server::DefaultRouter,
    time::StdClock,
    transport::linux::StdTransport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_lite::future::block_on(async {
        let mut socket = StdTransport::bind("127.0.0.1:0".parse().unwrap())?;
        let remote = socket.local_addr()?;
        let policy = PublicPaths(&[(Code::GET, "/counter")]);
        let mut counter = 0u32;
        let mut resource = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            counter += 1;
            response.set_payload(counter.to_string().as_bytes())?;
            Ok(Disposition::Complete)
        };
        let mut router = DefaultRouter::new(&policy);
        router.route("/counter", &[Code::GET], &mut resource)?;
        let resource_id = router.observable(
            "/counter",
            Settings::new(1)
                .with_minimum_ms(100)
                .with_maximum_ms(500)
                .with_confirmable_ms(1000),
        )?;
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
        let clock = StdClock::default();
        race(
            async {
                router.run(&mut endpoint, &mut socket, &clock).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let handle = shared.handle();
                let mut observation = handle.client(remote).observe("/counter")?;
                for _ in 0..3 {
                    let reply = observation.next().await.ok_or("observation ended")??;
                    println!(
                        "counter: {}",
                        String::from_utf8_lossy(reply.message()?.payload())
                    );
                    handle.notify(resource_id)?;
                }
                observation.cancel();
                Ok(())
            },
        )
        .await
    })
}
