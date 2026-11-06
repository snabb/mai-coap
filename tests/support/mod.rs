#![allow(dead_code)]
#[cfg(any(feature = "server", feature = "client"))]
mod outgoing;
#[cfg(any(feature = "server", feature = "client"))]
#[allow(unused_imports)]
pub use outgoing::PopOutgoing;

use mai_coap::{
    time::{Clock, Instant},
    transport::{Datagram, Metadata, Transport},
};
use std::{
    cell::RefCell,
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    task::{Poll, Waker},
};

/// Decodes fixed-width hexadecimal fixture data, panicking on invalid input.
pub fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Deliver,
    Drop,
    Duplicate,
    Delay(u64),
    Unreachable,
}
#[derive(Clone, Debug)]
pub struct Sent {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
    pub at: Instant,
}
struct Queued {
    from: SocketAddr,
    to: SocketAddr,
    bytes: Vec<u8>,
    at: Instant,
}
#[derive(Default)]
struct State {
    now: Instant,
    delay: u64,
    actions: Vec<Action>,
    sent: Vec<Sent>,
    packets: Vec<Queued>,
    unreachable: Vec<SocketAddr>,
    wakers: Vec<Waker>,
}
#[derive(Clone, Default)]
pub struct Network(Rc<RefCell<State>>);
impl Network {
    pub fn configure(&self, delay: u64, actions: &[Action]) {
        let mut state = self.0.borrow_mut();
        state.delay = delay;
        state.actions = actions.to_vec();
    }
    pub fn socket(&self, address: &str) -> Socket {
        Socket {
            network: self.clone(),
            local: address.parse().unwrap(),
        }
    }
    pub fn advance(&self, millis: u64) {
        let wakers = {
            let mut state = self.0.borrow_mut();
            state.now = state.now.after(millis);
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
    pub fn sent(&self) -> Vec<Sent> {
        self.0.borrow().sent.clone()
    }
    pub fn inject(&self, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        let mut state = self.0.borrow_mut();
        let at = state.now;
        state.packets.push(Queued {
            from,
            to,
            bytes: bytes.to_vec(),
            at,
        });
    }
}
impl Clock for Network {
    fn now(&self) -> Instant {
        self.0.borrow().now
    }
    async fn sleep_until(&self, deadline: Instant) {
        poll_fn(|cx| {
            let mut state = self.0.borrow_mut();
            if state.now >= deadline {
                Poll::Ready(())
            } else {
                if !state.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                    state.wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;
    }
}
pub struct Socket {
    network: Network,
    pub local: SocketAddr,
}
#[derive(Debug, Eq, PartialEq)]
pub struct Unreachable;
impl Transport for Socket {
    type Error = Unreachable;
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
impl mai_coap::transport::DatagramReceiver for &Socket {
    type Error = Unreachable;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;
    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Unreachable> {
        let packet = poll_fn(|cx| {
            let mut state = self.network.0.borrow_mut();
            if let Some(i) = state
                .unreachable
                .iter()
                .position(|local| *local == self.local)
            {
                state.unreachable.swap_remove(i);
                return Poll::Ready(Err(Unreachable));
            }
            if let Some(i) = state
                .packets
                .iter()
                .position(|p| p.to == self.local && p.at <= state.now)
            {
                return Poll::Ready(Ok(state.packets.remove(i)));
            }
            if !state.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                state.wakers.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await?;
        let n = scratch.len().min(packet.bytes.len());
        scratch[..n].copy_from_slice(&packet.bytes[..n]);
        Ok(Datagram {
            bytes: &scratch[..n],
            metadata: Metadata::new(packet.from, packet.to.ip(), packet.bytes.len())
                .with_interface(Some(1)),
        })
    }
}
impl mai_coap::transport::DatagramSender for &Socket {
    type Error = Unreachable;
    fn poll_send(
        &mut self,
        to: SocketAddr,
        source: Option<IpAddr>,
        _: Option<u32>,
        bytes: &[u8],
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        core::task::Poll::Ready(
            {
                let mut state = self.network.0.borrow_mut();
                let from = SocketAddr::new(source.unwrap_or(self.local.ip()), self.local.port());
                let action = state
                    .actions
                    .get(state.sent.len())
                    .copied()
                    .unwrap_or(Action::Deliver);
                let now = state.now;
                state.sent.push(Sent {
                    from,
                    to,
                    bytes: bytes.to_vec(),
                    at: now,
                });
                let at = now.after(
                    state.delay
                        + if let Action::Delay(extra) = action {
                            extra
                        } else {
                            0
                        },
                );
                if matches!(action, Action::Unreachable) {
                    state.unreachable.push(self.local);
                } else if !matches!(action, Action::Drop) {
                    state.packets.push(Queued {
                        from,
                        to,
                        bytes: bytes.to_vec(),
                        at,
                    });
                    if matches!(action, Action::Duplicate) {
                        state.packets.push(Queued {
                            from,
                            to,
                            bytes: bytes.to_vec(),
                            at: at.after(1),
                        });
                    }
                }
                let wakers = std::mem::take(&mut state.wakers);
                drop(state);
                for waker in wakers {
                    waker.wake();
                }
                Ok(())
            }
            .map(|()| mai_coap::transport::SendOutcome::Accepted),
        )
    }
}
