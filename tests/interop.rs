//! Independent peers are invoked through their public command-line interface only.
#![cfg(all(
    feature = "std",
    feature = "server",
    feature = "client",
    feature = "block1"
))]
use mai_coap::{
    codec::{Code, ContentFormat, MessageView},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    security::{Policy, SecurityState},
    server::{Router, SliceBody},
    time::StdClock,
    transport::linux::StdTransport,
};
use std::{
    net::UdpSocket,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

struct Public;
impl Policy for Public {
    fn allow(&self, _: SecurityState, _: MessageView<'_>) -> bool {
        true
    }
}

async fn output(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("install libcoap CLI peers to run interoperability tests");
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            let result = child.wait_with_output().unwrap();
            panic!(
                "peer timed out: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        async_io::Timer::after(Duration::from_millis(10)).await;
    }
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

#[cfg(feature = "proxy")]
#[test]
fn tst_6_our_proxy_with_libcoap_client_and_server() {
    use mai_coap::proxy::{ForwardProxy, Routing};
    struct Route(std::net::SocketAddr);
    impl Routing for Route {
        fn allow(&self, _: std::net::SocketAddr, host: &str, port: u16) -> bool {
            matches!(host, "localhost" | "127.0.0.1") && port == self.0.port()
        }
        fn resolve(&self, host: &str, port: u16) -> Option<std::net::SocketAddr> {
            self.allow(self.0, host, port).then_some(self.0)
        }
    }
    futures_lite::future::block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let mut peer = Peer(
            Command::new("coap-server-notls")
                .args([
                    "-A",
                    "127.0.0.1",
                    "-p",
                    &address.port().to_string(),
                    "-v",
                    "0",
                    "-d",
                    "2",
                    "-e",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        async_io::Timer::after(Duration::from_millis(100)).await;
        assert!(peer.0.try_wait().unwrap().is_none());
        let shared = Shared::<1152, 8>::new();
        let mut endpoint =
            Endpoint::<_, 1152, 8, 32>::new(&shared, Unsecured(rand::rng())).unwrap();
        let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 1152>| Err(Code::NOT_FOUND);
        let mut proxy =
            ForwardProxy::<_, _, 1152, 8, 8>::new(local, Route(address), shared.handle()).unwrap();
        let mut transport = StdTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let proxy_address = transport.local_addr().unwrap();
        let clock = StdClock::default();
        let driver = endpoint.run(&mut transport, &clock, &mut proxy, &Public);
        let work = async {
            // The 4.3.4 CLI cannot follow Block2 in a separate CON response.
            // Use NON here; the PUT below still exercises a CON proxy exchange.
            let result = output(Command::new("coap-client-notls").args([
                "-v",
                "0",
                "-B",
                "5",
                "-N",
                "-U",
                "-P",
                &format!("coap://{proxy_address}"),
                "-b",
                "16",
                &format!("coap://localhost:{}/.well-known/core", address.port()),
            ]))
            .await;
            assert!(result.status.success());
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("</time>"),
                "{} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            let result = output(Command::new("coap-client-notls").args([
                "-v",
                "0",
                "-B",
                "5",
                "-U",
                "-P",
                &format!("coap://{proxy_address}"),
                "-m",
                "put",
                "-e",
                "through proxy",
                &format!("coap://{address}/dynamic"),
            ]))
            .await;
            assert!(result.status.success());
            assert_eq!(
                String::from_utf8_lossy(&result.stdout).trim(),
                "through proxy"
            );
        };
        futures_lite::future::race(
            async {
                driver.await.unwrap();
                panic!("driver stopped")
            },
            work,
        )
        .await;
    });
}

#[test]
fn tst_6_libcoap_client_to_server_hostname_literal_and_blocks() {
    futures_lite::future::block_on(async {
        let shared = Shared::<1152, 4>::new();
        let mut endpoint =
            Endpoint::<_, 1152, 4, 16>::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut echo = |request: Request<'_>, response: &mut ResponseWriter<'_, 1152>| {
            response.set_code(Code::CHANGED);
            response
                .set_payload(request.payload().len().to_string().as_bytes())
                .unwrap();
            Ok(Disposition::Complete)
        };
        let body = [b'z'; 3000];
        let mut source = {
            let mut body = SliceBody::new(&body, ContentFormat::TEXT);
            body.etag = b"fixed";
            body.max_age = 60;
            body
        };
        let mut router = Router::<1152>::new(&Public);
        router.set_block_caps(6, 6).unwrap();
        router
            .buffered_upload("/echo", &[Code::POST], &mut echo)
            .unwrap();
        router.representation("/large", &mut source).unwrap();
        // Hostname resolution may prefer either loopback address family.
        let mut transport = StdTransport::bind("[::]:0".parse().unwrap()).unwrap();
        let port = transport.local_addr().unwrap().port();
        let clock = StdClock::default();
        let driver = endpoint.run(&mut transport, &clock, &mut router, &Public);
        let work = async {
            for host in ["127.0.0.1", "[::1]", "localhost"] {
                let result = output(Command::new("coap-client-notls").args([
                    "-v",
                    "0",
                    "-B",
                    "5",
                    "-b",
                    "64",
                    &format!("coap://{host}:{port}/large"),
                ]))
                .await;
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let actual = result.stdout.strip_suffix(b"\n").unwrap_or(&result.stdout);
                assert!(
                    actual == body,
                    "response length {}, expected {}",
                    actual.len(),
                    body.len()
                );
            }
            let payload = "upload".repeat(250);
            let result = output(Command::new("coap-client-notls").args([
                "-v",
                "0",
                "-B",
                "5",
                "-b",
                "128",
                "-m",
                "post",
                "-e",
                &payload,
                &format!("coap://127.0.0.1:{port}/echo"),
            ]))
            .await;
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                String::from_utf8(result.stdout).unwrap().trim(),
                payload.len().to_string()
            );
        };
        futures_lite::future::race(
            async {
                driver.await.unwrap();
                panic!("driver stopped")
            },
            work,
        )
        .await;
    });
}

#[test]
fn tst_6_libcoap_server_to_client_and_block2() {
    futures_lite::future::block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let mut peer = Peer(
            Command::new("coap-server-notls")
                .args([
                    "-A",
                    "127.0.0.1",
                    "-p",
                    &address.port().to_string(),
                    "-v",
                    "0",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("install libcoap CLI peers"),
        );
        async_io::Timer::after(Duration::from_millis(100)).await;
        assert!(peer.0.try_wait().unwrap().is_none());
        let shared = Shared::<1152, 4>::new();
        let mut endpoint =
            Endpoint::<_, 1152, 4, 16>::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut transport = StdTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let clock = StdClock::default();
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 1152>| Err(Code::NOT_FOUND);
        let driver = endpoint.run(&mut transport, &clock, &mut app, &Public);
        let work = async {
            let response = shared.handle().client(address).get("/time").await.unwrap();
            assert!(!response.message().unwrap().payload().is_empty());
            let mut bytes = [0; 4096];
            let n = shared
                .handle()
                .client(address)
                .get_blocks("/.well-known/core", 2, &mut bytes)
                .await
                .unwrap();
            assert!(n > 64);
            assert!(String::from_utf8_lossy(&bytes[..n]).contains("</time>"));
        };
        let test = futures_lite::future::race(
            async {
                driver.await.unwrap();
                panic!("driver stopped")
            },
            work,
        );
        futures_lite::future::race(test, async {
            async_io::Timer::after(Duration::from_secs(10)).await;
            panic!("interop deadline")
        })
        .await;
    });
}
