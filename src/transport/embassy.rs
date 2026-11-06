//! Embassy UDP metadata mapping (TR-6).
use super::{Datagram, DatagramReceiver, DatagramSender, Metadata, SendOutcome, Transport};
use core::net::{IpAddr, SocketAddr};

/// Application-created Embassy UDP socket with receive destination metadata.
pub struct EmbassyTransport<'a> {
    /// Socket on the application's running network stack.
    pub socket: embassy_net::udp::UdpSocket<'a>,
}
/// Embassy socket or missing-metadata error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum EmbassyError {
    /// Sending failed.
    Send(embassy_net::udp::SendError),
    /// A receive lacked required destination information.
    MissingDestination,
    /// The adapter disables this family, or source and destination families differ.
    UnsupportedAddressFamily,
}
impl core::fmt::Display for EmbassyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Send(error) => write!(f, "UDP send failed: {error:?}"),
            Self::MissingDestination => f.write_str("UDP destination metadata missing"),
            Self::UnsupportedAddressFamily => f.write_str("UDP address family is unavailable"),
        }
    }
}
impl core::error::Error for EmbassyError {}
impl Transport for EmbassyTransport<'_> {
    type Error = EmbassyError;
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
impl DatagramReceiver for &EmbassyTransport<'_> {
    type Error = EmbassyError;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;
    fn discard_receive_error(error: &Self::Error) -> bool {
        matches!(error, EmbassyError::MissingDestination)
    }
    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
        loop {
            match self.socket.recv_from(scratch).await {
                Ok((length, meta)) => {
                    let local = meta.local_address.ok_or(EmbassyError::MissingDestination)?;
                    let remote = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                    return Ok(Datagram {
                        bytes: &scratch[..length],
                        metadata: Metadata {
                            remote,
                            local: local.into(),
                            interface: None,
                            original_len: length,
                        },
                    });
                }
                Err(embassy_net::udp::RecvError::Truncated) => { /* TR-4: discard the whole oversized packet. */
                }
            }
        }
    }
}
impl DatagramSender for &EmbassyTransport<'_> {
    type Error = EmbassyError;
    fn discard_send_error(error: &Self::Error) -> bool {
        matches!(
            error,
            EmbassyError::UnsupportedAddressFamily
                | EmbassyError::Send(
                    embassy_net::udp::SendError::NoRoute
                        | embassy_net::udp::SendError::PacketTooLarge
                )
        )
    }
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        _: Option<u32>,
        bytes: &[u8],
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<SendOutcome, Self::Error>> {
        if source.is_some_and(|address| address.is_ipv4() != remote.is_ipv4()) {
            return core::task::Poll::Ready(Err(EmbassyError::UnsupportedAddressFamily));
        }
        let remote_address = ip_address(remote.ip())?;
        let mut metadata = embassy_net::udp::UdpMetadata::from(embassy_net::IpEndpoint {
            addr: remote_address,
            port: remote.port(),
        });
        metadata.local_address = source.map(ip_address).transpose()?;
        self.socket.poll_send_to(bytes, metadata, cx).map(|result| {
            result
                .map(|()| SendOutcome::Accepted)
                .map_err(EmbassyError::Send)
        })
    }
}

fn ip_address(address: IpAddr) -> Result<embassy_net::IpAddress, EmbassyError> {
    match address {
        IpAddr::V4(address) => {
            #[cfg(feature = "embassy-net-ipv4")]
            {
                Ok(address.into())
            }
            #[cfg(not(feature = "embassy-net-ipv4"))]
            {
                let _ = address;
                Err(disabled_family("embassy-net-ipv4"))
            }
        }
        IpAddr::V6(address) => {
            #[cfg(feature = "embassy-net-ipv6")]
            {
                Ok(address.into())
            }
            #[cfg(not(feature = "embassy-net-ipv6"))]
            {
                let _ = address;
                Err(disabled_family("embassy-net-ipv6"))
            }
        }
    }
}

#[cfg(not(all(feature = "embassy-net-ipv4", feature = "embassy-net-ipv6")))]
fn disabled_family(
    #[cfg_attr(not(any(feature = "log", feature = "defmt")), expect(unused_variables))]
    feature: &'static str,
) -> EmbassyError {
    #[cfg(any(feature = "log", feature = "defmt"))]
    {
        static WARNED: critical_section::Mutex<core::cell::Cell<bool>> =
            critical_section::Mutex::new(core::cell::Cell::new(false));
        crate::transport::warn_once(&WARNED, || {
            #[cfg(feature = "log")]
            log::warn!(
                "mai-coap: Embassy send uses a disabled address family; enable mai-coap/{feature}"
            );
            #[cfg(feature = "defmt")]
            defmt::warn!(
                "mai-coap: Embassy send uses a disabled address family; enable mai-coap/{=str}",
                feature
            );
        });
    }
    EmbassyError::UnsupportedAddressFamily
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        any(feature = "log", feature = "defmt"),
        not(all(feature = "embassy-net-ipv4", feature = "embassy-net-ipv6"))
    ))]
    #[test]
    fn disabled_family_warning_is_once_even_with_reentry() {
        use core::cell::Cell;
        let latch = critical_section::Mutex::new(Cell::new(false));
        let warnings = Cell::new(0);
        for _ in 0..3 {
            crate::transport::warn_once(&latch, || {
                warnings.set(warnings.get() + 1);
                crate::transport::warn_once(&latch, || {
                    panic!("warning repeated during logger reentry")
                });
            });
        }
        assert_eq!(warnings.get(), 1);
    }

    #[test]
    fn tr_6_ip_conversion_matches_enabled_protocol_families() {
        #[cfg(feature = "embassy-net-ipv4")]
        assert_eq!(
            ip_address(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST)),
            Ok(embassy_net::IpAddress::Ipv4(
                embassy_net::Ipv4Address::LOCALHOST
            ))
        );
        #[cfg(not(feature = "embassy-net-ipv4"))]
        assert_eq!(
            ip_address(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST)),
            Err(EmbassyError::UnsupportedAddressFamily)
        );

        #[cfg(feature = "embassy-net-ipv6")]
        assert_eq!(
            ip_address(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST)),
            Ok(embassy_net::IpAddress::Ipv6(
                embassy_net::Ipv6Address::LOCALHOST
            ))
        );
        #[cfg(not(feature = "embassy-net-ipv6"))]
        assert_eq!(
            ip_address(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST)),
            Err(EmbassyError::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn tr_5_send_errors_are_dropped_only_when_destination_specific() {
        assert!(<&EmbassyTransport>::discard_send_error(
            &EmbassyError::UnsupportedAddressFamily
        ));
        assert!(<&EmbassyTransport>::discard_send_error(
            &EmbassyError::Send(embassy_net::udp::SendError::NoRoute)
        ));
        assert!(<&EmbassyTransport>::discard_send_error(
            &EmbassyError::Send(embassy_net::udp::SendError::PacketTooLarge)
        ));
        assert!(!<&EmbassyTransport>::discard_send_error(
            &EmbassyError::Send(embassy_net::udp::SendError::SocketNotBound)
        ));
    }
}
