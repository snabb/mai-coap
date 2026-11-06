//! Loopback-only host link for black-box testing of the native xarxa adapter.
//! Linux carries UDP payloads; xarxa still processes the synthesized IP packets.
use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::pin,
    task::{Poll, Waker},
};
use mai_coap::{
    XarxaStorage,
    endpoint::{Application, DefaultEndpoint, DefaultShared, Protection},
    security::Policy,
    time::{Clock, StdClock},
    transport::xarxa::{StackAccess, XarxaTransport},
};
use std::{
    error::Error,
    io,
    io::Write,
    net::{SocketAddr, UdpSocket},
    rc::Rc,
    time::Duration,
};
use xarxa::{
    Pool, StaticPool,
    driver::{
        Capabilities, ChecksumCapabilities, Driver, HardwareAddress, Medium, NotSupported,
        PacketBuf,
    },
    wire::{IpCidr, Ipv4Packet, UdpPacket},
};

static POOL: StaticPool<1536, 64> = StaticPool::new();
struct Device {
    socket: UdpSocket,
    local: std::net::SocketAddrV4,
    failure: Rc<RefCell<Option<io::Error>>>,
}
impl Driver for Device {
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities.checksum = ChecksumCapabilities::all_offloaded();
        capabilities
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ip
    }
    fn register_waker(&mut self, _: &Waker) -> Result<(), NotSupported> {
        Ok(())
    }
    fn rx_wanted(&mut self) -> usize {
        0
    }
    fn rx_give(&mut self, _: PacketBuf) {}
    fn receive(&mut self) -> Option<PacketBuf> {
        let mut packet = POOL.alloc()?;
        packet.set_len(1536);
        let (length, remote) = match self.socket.recv_from(&mut packet[28..]) {
            Ok((length, SocketAddr::V4(remote))) => (length, remote),
            Ok(_) => return None,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return None,
            Err(error) => {
                *self.failure.borrow_mut() = Some(error);
                return None;
            }
        };
        packet.set_len(28 + length);
        packet[..28].fill(0);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((28 + length) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&remote.ip().octets());
        packet[16..20].copy_from_slice(&self.local.ip().octets());
        packet[20..22].copy_from_slice(&remote.port().to_be_bytes());
        packet[22..24].copy_from_slice(&self.local.port().to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + length) as u16).to_be_bytes());
        Some(packet)
    }
    fn can_transmit(&mut self) -> bool {
        self.failure.borrow().is_none()
    }
    fn transmit(&mut self, mut packet: PacketBuf) -> Result<(), PacketBuf> {
        let result = (|| -> io::Result<()> {
            let mut ip = Ipv4Packet::new_checked(&mut packet[..])
                .map_err(|_| io::Error::other("invalid emitted IPv4 packet"))?;
            let destination = ip.dst_addr();
            let udp = UdpPacket::new_checked(ip.payload_mut())
                .map_err(|_| io::Error::other("invalid emitted UDP packet"))?;
            let remote = SocketAddr::from((destination, udp.dst_port()));
            self.socket.send_to(udp.payload(), remote)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                *self.failure.borrow_mut() = Some(error);
                Err(packet)
            }
        }
    }
}
#[derive(Clone, Copy)]
struct Access<'s, 'd> {
    stack: &'s RefCell<xarxa::Stack<'d>>,
    requested: &'s Cell<bool>,
    waker: &'s RefCell<Option<Waker>>,
}
impl<'d> StackAccess<'d> for Access<'_, 'd> {
    fn with_stack<R>(&self, operation: impl FnOnce(&mut xarxa::Stack<'d>) -> R) -> R {
        operation(&mut self.stack.borrow_mut())
    }
    fn wake_runner(&self) {
        self.requested.set(true);
        let waker = self.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
pub fn serve<P: Protection, A: Application<1152>>(
    bind: SocketAddr,
    shared: &DefaultShared,
    protection: P,
    application: &mut A,
    policy: &impl Policy,
) -> Result<(), Box<dyn Error>> {
    let SocketAddr::V4(bind) = bind else {
        return Err("xarxa host link requires IPv4 loopback".into());
    };
    if !bind.ip().is_loopback() {
        return Err("xarxa host link requires IPv4 loopback".into());
    }
    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let SocketAddr::V4(local) = socket.local_addr()? else {
        return Err("IPv4 socket required".into());
    };
    let failure = Rc::new(RefCell::new(None));
    let mut device = Device {
        socket,
        local,
        failure: failure.clone(),
    };
    #[cfg(feature = "embassy-net-xarxa-ipv4")]
    if std::env::var("MAI_COAP_XARXA").as_deref() == Ok("embassy") {
        return serve_embassy(device, shared, protection, application, policy);
    }

    let mut stack = xarxa::Stack::new(&POOL, 123);
    let iface = stack.add_iface_borrowed(&mut device)?;
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new((*local.ip()).into(), 8))?;
    let handle = stack.add_udp_socket()?;
    stack.udp_socket(handle).bind_to_iface(Some(iface))?;
    stack.udp_socket(handle).bind(local.port(), 0)?;
    let stack = RefCell::new(stack);
    let requested = Cell::new(false);
    let waker = RefCell::new(None);
    let access = Access {
        stack: &stack,
        requested: &requested,
        waker: &waker,
    };
    let storage =
        XarxaStorage::<_, 40>::new(|| access.with_stack(|stack| stack.udp_socket(handle).alloc()));
    let mut endpoint = DefaultEndpoint::with_storage(shared, protection, storage)?;
    let mut transport = XarxaTransport::new(access, handle, iface, 1)?;
    let clock = StdClock::default();
    println!("LISTEN {local}");
    io::stdout().flush()?;
    let runner = async {
        loop {
            access.with_stack(|stack| {
                stack.poll(xarxa::time::Instant::from_millis(clock.now().0 as u32))
            });
            if let Some(error) = failure.borrow_mut().take() {
                return Err::<(), Box<dyn Error>>(error.into());
            }
            let mut timer = pin!(async_io::Timer::after(Duration::from_millis(1)));
            poll_fn(|cx| {
                *waker.borrow_mut() = Some(cx.waker().clone());
                if requested.replace(false) || timer.as_mut().poll(cx).is_ready() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    };
    let driver = async {
        endpoint
            .run_owned(&mut transport, &clock, application, policy)
            .await
            .map_err(|error| Box::new(error) as Box<dyn Error>)
    };
    futures_lite::future::block_on(futures_lite::future::race(driver, runner))
}

#[cfg(feature = "embassy-net-xarxa-ipv4")]
fn serve_embassy<P: Protection, A: Application<1152>>(
    mut device: Device,
    shared: &DefaultShared,
    protection: P,
    application: &mut A,
    policy: &impl Policy,
) -> Result<(), Box<dyn Error>> {
    use mai_coap::transport::embassy_xarxa::EmbassyXarxaTransport;
    let local = device.local;
    let failure = device.failure.clone();
    let mut storage = embassy_net_xarxa::StackStorage::new();
    let (stack, mut runner) = embassy_net_xarxa::Stack::new(&mut storage, &POOL, 123);
    let iface = stack.add_iface_borrowed(&mut device)?;
    iface.add_ip_addr(IpCidr::new((*local.ip()).into(), 8))?;
    let iface = iface.handle();
    let mut socket = embassy_net_xarxa::udp::UdpSocket::new(stack)?;
    socket.bind_to_iface(Some(iface))?;
    socket.bind(local.port(), 0)?;
    let storage = XarxaStorage::<_, 40>::new(|| socket.try_alloc());
    let mut endpoint = DefaultEndpoint::with_storage(shared, protection, storage)?;
    let clock = StdClock::default();
    let mut transport = EmbassyXarxaTransport::new(&socket, iface, 1)?;
    println!("LISTEN {local}");
    io::stdout().flush()?;
    let run = async {
        let mut runner = pin!(runner.run());
        loop {
            poll_fn(|cx| {
                let _ = runner.as_mut().poll(cx);
                Poll::Ready(())
            })
            .await;
            if let Some(error) = failure.borrow_mut().take() {
                return Err::<(), Box<dyn Error>>(error.into());
            }
            // This host link has no driver interrupt; poll for incoming UDP every millisecond.
            async_io::Timer::after(Duration::from_millis(1)).await;
        }
    };
    let driver = async {
        endpoint
            .run_owned(&mut transport, &clock, application, policy)
            .await
            .map_err(|error| Box::new(error) as Box<dyn Error>)
    };
    futures_lite::future::block_on(futures_lite::future::race(driver, run))
}
