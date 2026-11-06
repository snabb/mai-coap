//! Linux metadata and truncation tests (TR-1–4), using real UDP datagrams.
#![cfg(all(feature = "std", target_os = "linux"))]
use mai_coap::transport::{DatagramReceiver, DatagramSender, ReceivedPacket, linux::StdTransport};
#[test]
fn tr_5_destination_send_failures_are_discardable_but_socket_errors_are_fatal() {
    use std::io::{Error, ErrorKind};

    assert!(<&StdTransport>::discard_send_error(&Error::from(
        ErrorKind::HostUnreachable
    )));
    assert!(<&StdTransport>::discard_send_error(&Error::from(
        ErrorKind::NetworkUnreachable
    )));
    assert!(<&StdTransport>::discard_send_error(
        &Error::from_raw_os_error(nix::libc::EMSGSIZE)
    ));
    assert!(!<&StdTransport>::discard_send_error(&Error::from(
        ErrorKind::PermissionDenied
    )));
}

#[test]
fn tr_1_2_4_destination_source_and_original_length() {
    futures_lite::future::block_on(async {
        let server = StdTransport::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let port = server.local_addr().unwrap().port();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        peer.send_to(&[7; 100], ("127.0.0.2", port)).unwrap();
        let mut small = [0u8; 16];
        let mut receiver = &server;
        let packet = receiver.receive(&mut small).await.unwrap();
        assert_eq!(packet.bytes(), &[7; 16]);
        let metadata = packet.metadata();
        assert_eq!(metadata.original_len, 100);
        assert_eq!(
            metadata.local,
            "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
        );
        core::future::poll_fn(|cx| {
            (&server).poll_send(
                metadata.remote,
                Some(metadata.local),
                metadata.interface,
                b"ok",
                cx,
            )
        })
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        let (n, remote) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");
        assert_eq!(remote.ip(), metadata.local);
    });
}
#[test]
fn tr_1_ipv6_packet_info() {
    futures_lite::future::block_on(async {
        let server = StdTransport::bind("[::]:0".parse().unwrap()).unwrap();
        let port = server.local_addr().unwrap().port();
        let peer = std::net::UdpSocket::bind("[::1]:0").unwrap();
        peer.send_to(b"v6", ("::1", port)).unwrap();
        let mut buf = [0; 32];
        let mut receiver = &server;
        let received = receiver.receive(&mut buf).await.unwrap();
        assert_eq!(
            received.metadata().local,
            "::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(received.bytes(), b"v6");
    });
}

#[cfg(all(feature = "server", feature = "client"))]
mod send_error_endpoint {
    use core::net::{IpAddr, SocketAddr};
    use mai_coap::{
        codec::{Code, MessageBuilder, MessageType, OptionNumber},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        time::{Clock, Instant},
        transport::{Datagram, Metadata, Transport},
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        Destination,
        Stop,
    }

    struct ScriptedTransport {
        request: [u8; 32],
        length: usize,
        receives: core::cell::Cell<usize>,
        sends: core::cell::Cell<usize>,
    }

    impl Transport for ScriptedTransport {
        type Error = Failure;
        type Receiver<'a>
            = &'a Self
        where
            Self: 'a;
        type Sender<'a>
            = &'a Self
        where
            Self: 'a;
        fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
            (self, self)
        }
    }
    impl mai_coap::transport::DatagramReceiver for &ScriptedTransport {
        type Error = Failure;
        type Packet<'a>
            = Datagram<'a>
        where
            Self: 'a;

        async fn receive<'a>(
            &'a mut self,
            scratch: &'a mut [u8],
        ) -> Result<Datagram<'a>, Self::Error> {
            if self.receives.get() == 2 {
                return Err(Failure::Stop);
            }
            self.receives.set(self.receives.get() + 1);
            scratch[..self.length].copy_from_slice(&self.request[..self.length]);
            if self.receives.get() > 1 {
                scratch[2..4].copy_from_slice(&2u16.to_be_bytes());
            }
            Ok(Datagram {
                bytes: &scratch[..self.length],
                metadata: Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    self.length,
                ),
            })
        }
    }
    impl mai_coap::transport::DatagramSender for &ScriptedTransport {
        type Error = Failure;
        fn discard_send_error(error: &Self::Error) -> bool {
            *error == Failure::Destination
        }
        fn poll_send(
            &mut self,
            _: SocketAddr,
            _: Option<IpAddr>,
            _: Option<u32>,
            _: &[u8],
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
            core::task::Poll::Ready(
                {
                    self.sends.set(self.sends.get() + 1);
                    if self.sends.get() == 1 {
                        Err(Failure::Destination)
                    } else {
                        Ok(())
                    }
                }
                .map(|()| mai_coap::transport::SendOutcome::Accepted),
            )
        }
    }

    struct ClockStub;
    impl Clock for ClockStub {
        fn now(&self) -> Instant {
            Instant(0)
        }
        async fn sleep_until(&self, _: Instant) {
            core::future::pending().await
        }
    }

    #[test]
    fn tr_5_destination_send_error_drops_one_reply_and_driver_continues() {
        futures_lite::future::block_on(async {
            let mut request = [0; 32];
            let mut builder =
                MessageBuilder::new(&mut request, MessageType::Confirmable, Code::GET, 1, b"t")
                    .unwrap();
            builder.option(OptionNumber::URI_PATH, b"x").unwrap();
            let length = builder.finish(&[]).unwrap();
            let mut transport = ScriptedTransport {
                request,
                length,
                receives: core::cell::Cell::new(0),
                sends: core::cell::Cell::new(0),
            };
            let shared = Shared::<128, 1>::new();
            let mut endpoint =
                Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
            let mut handled = 0;
            let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
                handled += 1;
                response.set_payload(b"reply").unwrap();
                Ok(Disposition::Complete)
            };
            let result = endpoint
                .run(
                    &mut transport,
                    &ClockStub,
                    &mut app,
                    &PublicPaths(&[(Code::GET, "/x")]),
                )
                .await;
            assert!(matches!(
                result,
                Err(mai_coap::endpoint::RunError::Transport(Failure::Stop))
            ));
            assert_eq!(handled, 2);
            assert_eq!(transport.sends.get(), 2);
            assert_eq!(endpoint.counters().send_failures, 1);
            assert_eq!(endpoint.counters().dropped_messages, 1);
        });
    }
}
