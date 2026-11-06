//! Linux UDP sockets with destination/source packet information (TR-1–4).
use super::{Datagram, DatagramReceiver, DatagramSender, Metadata, SendOutcome, Transport};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use nix::{
    libc,
    sys::socket::{self, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use std::vec;
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::UdpSocket,
    os::fd::AsRawFd,
};

/// Nonblocking std socket using safe packet-info APIs and readiness waits.
#[derive(Debug)]
pub struct StdTransport {
    socket: async_io::Async<UdpSocket>,
}
impl StdTransport {
    /// Binds a new socket. Group membership remains the application's responsibility.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::from_socket(UdpSocket::bind(address)?)
    }
    /// Adopts a socket, enabling packet info before receiving any datagram.
    pub fn from_socket(socket: UdpSocket) -> io::Result<Self> {
        if socket.local_addr()?.is_ipv4() {
            socket::setsockopt(&socket, socket::sockopt::Ipv4PacketInfo, &true)?;
        } else {
            socket::setsockopt(&socket, socket::sockopt::Ipv6RecvPacketInfo, &true)?;
            socket::setsockopt(&socket, socket::sockopt::Ipv4PacketInfo, &true)?;
        }
        Ok(Self {
            socket: async_io::Async::new(socket)?,
        })
    }
    /// Underlying std socket for multicast membership and socket configuration.
    pub fn socket(&self) -> &UdpSocket {
        self.socket.get_ref()
    }
    /// Bound address, including an automatically assigned port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket().local_addr()
    }
}
impl Transport for StdTransport {
    type Error = io::Error;
    type Receiver<'a> = &'a Self;
    type Sender<'a> = &'a Self;
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
        (self, self)
    }
}
impl DatagramReceiver for &StdTransport {
    type Error = io::Error;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;
    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> io::Result<Datagram<'a>> {
        let metadata = self
            .socket
            .read_with(|socket| {
                let mut iov = [IoSliceMut::new(scratch)];
                let mut control = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo);
                let message = socket::recvmsg::<SockaddrStorage>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    MsgFlags::MSG_TRUNC | MsgFlags::MSG_DONTWAIT,
                )?;
                let address = message.address.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing UDP sender")
                })?;
                let remote = if let Some(a) = address.as_sockaddr_in() {
                    SocketAddr::from(*a)
                } else if let Some(a) = address.as_sockaddr_in6() {
                    SocketAddr::from(*a)
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported UDP address",
                    ));
                };
                let mut destination = None;
                for cmsg in message.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv4PacketInfo(info) => {
                            destination = Some((
                                IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                                info.ipi_ifindex as u32,
                            ))
                        }
                        ControlMessageOwned::Ipv6PacketInfo(info) => {
                            destination = Some((
                                IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                                info.ipi6_ifindex,
                            ))
                        }
                        _ => {}
                    }
                }
                let (local, interface) = destination.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing UDP destination")
                })?;
                Ok(Metadata {
                    remote,
                    local,
                    interface: Some(interface),
                    original_len: message.bytes,
                })
            })
            .await?;
        Ok(Datagram {
            bytes: &scratch[..metadata.original_len.min(scratch.len())],
            metadata,
        })
    }
}
impl DatagramSender for &StdTransport {
    type Error = io::Error;
    fn discard_send_error(error: &Self::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
        ) || error.raw_os_error() == Some(nix::libc::EMSGSIZE)
    }
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<SendOutcome>> {
        if source.is_some_and(|a| a.is_multicast()) {
            return core::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multicast UDP source",
            )));
        }
        let address = SockaddrStorage::from(remote);
        let result = (|| {
            let socket = self.socket.get_ref();
            let iov = [IoSlice::new(bytes)];
            let mut v4 = libc::in_pktinfo {
                ipi_ifindex: interface.unwrap_or(0) as i32,
                ipi_spec_dst: libc::in_addr { s_addr: 0 },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            let mut v6 = libc::in6_pktinfo {
                ipi6_ifindex: interface.unwrap_or(0),
                ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
            };
            let mut cmsgs = std::vec::Vec::with_capacity(1);
            match source {
                Some(IpAddr::V4(a)) => {
                    v4.ipi_spec_dst.s_addr = u32::from_ne_bytes(a.octets());
                    cmsgs.push(ControlMessage::Ipv4PacketInfo(&v4));
                }
                Some(IpAddr::V6(a)) => {
                    v6.ipi6_addr.s6_addr = a.octets();
                    cmsgs.push(ControlMessage::Ipv6PacketInfo(&v6));
                }
                None if interface.is_some() && remote.is_ipv4() => {
                    cmsgs.push(ControlMessage::Ipv4PacketInfo(&v4))
                }
                None if interface.is_some() => cmsgs.push(ControlMessage::Ipv6PacketInfo(&v6)),
                None => {}
            }
            let n = socket::sendmsg(
                socket.as_raw_fd(),
                &iov,
                &cmsgs,
                MsgFlags::MSG_DONTWAIT,
                Some(&address),
            )?;
            if n != bytes.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
            }
            Ok(())
        })();
        match result {
            Ok(()) => core::task::Poll::Ready(Ok(SendOutcome::Accepted)),
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                core::task::Poll::Ready(Ok(SendOutcome::RetryLater))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // poll_writable consumes stale readiness. Fall back to the endpoint's
                // timer if it reports an event without accepting this datagram.
                self.socket
                    .poll_writable(cx)
                    .map(|result| result.map(|()| SendOutcome::RetryLater))
            }
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    }
}
