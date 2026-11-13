//! Receive priority and cancellation while waiting for driver work.
#![cfg(all(feature = "server", feature = "client"))]
mod support;

use core::{
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    task::{Context, Poll, Waker},
};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, RunError, Shared, Unsecured},
    security::AllowAll,
    time::{Clock, Instant},
    transport::{Datagram, Metadata, Transport},
};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct State {
    incoming: Option<(Vec<u8>, Metadata)>,
    receives_active: usize,
    receives_cancelled: usize,
    timer_ready: bool,
    arrive_on_timer: bool,
    timer_polls: usize,
    sent: usize,
}

struct ReceiveGuard {
    state: Rc<RefCell<State>>,
    completed: bool,
}
impl Drop for ReceiveGuard {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        state.receives_active -= 1;
        state.receives_cancelled += usize::from(!self.completed);
    }
}

struct Socket(Rc<RefCell<State>>);
#[derive(Debug)]
struct Stop;
impl Transport for Socket {
    type Error = Stop;
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
    type Error = Stop;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;

    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Stop> {
        self.0.borrow_mut().receives_active += 1;
        let mut guard = ReceiveGuard {
            state: self.0.clone(),
            completed: false,
        };
        let (bytes, metadata) = poll_fn(|_| {
            self.0
                .borrow_mut()
                .incoming
                .take()
                .map_or(Poll::Pending, Poll::Ready)
        })
        .await;
        scratch[..bytes.len()].copy_from_slice(&bytes);
        guard.completed = true;
        Ok(Datagram {
            bytes: &scratch[..bytes.len()],
            metadata,
        })
    }
}
impl mai_coap::transport::DatagramSender for &Socket {
    type Error = Stop;
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
                let mut state = self.0.borrow_mut();
                state.sent += 1;
                Err(Stop)
            }
            .map(|()| mai_coap::transport::SendOutcome::Accepted),
        )
    }
}

struct Timer(Rc<RefCell<State>>);
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant(0)
    }
    async fn sleep_until(&self, _: Instant) {
        poll_fn(|_| {
            let mut state = self.0.borrow_mut();
            state.timer_polls += 1;
            if state.timer_ready {
                state.timer_ready = false;
                if state.arrive_on_timer {
                    state.incoming = Some(packet());
                }
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

fn packet() -> (Vec<u8>, Metadata) {
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 42, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    (
        bytes[..n].to_vec(),
        Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            n,
        )
        .with_interface(Some(7)),
    )
}

#[test]
fn ready_receive_precedes_timer_and_driver_cancellation_preserves_arrivals() {
    for restart in [false, true] {
        let shared = Shared::<128, 1>::new();
        let mut endpoint =
            Endpoint::<_, 128, 1, 2, 0, 1, 2, 1, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
                .unwrap();
        let state = Rc::new(RefCell::new(State::default()));
        let mut socket = Socket(state.clone());
        let timer = Timer(state.clone());
        let mut seen = Vec::new();
        let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
            seen.push(request.metadata);
            Ok(Disposition::Complete)
        };
        let mut cx = Context::from_waker(Waker::noop());
        let incoming = packet();
        let metadata = incoming.1;
        {
            let mut driver =
                core::pin::pin!(endpoint.run(&mut socket, &timer, &mut app, &AllowAll));
            assert!(driver.as_mut().poll(&mut cx).is_pending());
            assert_eq!(state.borrow().timer_polls, 1);
            state.borrow_mut().incoming = Some(incoming);
            if !restart {
                state.borrow_mut().timer_ready = true;
                assert!(matches!(
                    driver.as_mut().poll(&mut cx),
                    Poll::Ready(Err(RunError::Transport(Stop)))
                ));
            }
        }
        if restart {
            assert_eq!(state.borrow().receives_cancelled, 1);
            assert!(state.borrow().incoming.is_some());
            let mut driver =
                core::pin::pin!(endpoint.run(&mut socket, &timer, &mut app, &AllowAll));
            assert!(matches!(
                driver.as_mut().poll(&mut cx),
                Poll::Ready(Err(RunError::Transport(Stop)))
            ));
        }
        assert_eq!(seen, [metadata]);
        let state = state.borrow();
        assert_eq!(state.timer_polls, 1);
        assert_eq!(state.receives_cancelled, usize::from(restart));
        assert_eq!(state.sent, 1);
    }
}

#[test]
fn command_or_timer_wake_allows_send_while_receive_is_pending() {
    for command in [false, true] {
        let shared = Shared::<128, 1>::new();
        let mut endpoint =
            Endpoint::<_, 128, 1, 2, 0, 1, 2, 1, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
                .unwrap();
        let state = Rc::new(RefCell::new(State::default()));
        let mut socket = Socket(state.clone());
        let timer = Timer(state.clone());
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        let mut cx = Context::from_waker(Waker::noop());
        let mut driver = core::pin::pin!(endpoint.run(&mut socket, &timer, &mut app, &AllowAll));
        assert!(driver.as_mut().poll(&mut cx).is_pending());
        let _operation = command.then(|| {
            shared
                .handle()
                .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
                .request(Code::GET, "/x")
                .unwrap()
                .send()
                .unwrap()
        });
        state.borrow_mut().timer_ready = true;
        state.borrow_mut().arrive_on_timer = !command;
        assert!(matches!(
            driver.as_mut().poll(&mut cx),
            Poll::Ready(Err(RunError::Transport(Stop)))
        ));
        let state = state.borrow();
        assert_eq!(state.receives_cancelled, if command { 1 } else { 2 });
        assert_eq!(state.timer_polls, if command { 1 } else { 2 });
        assert_eq!(state.sent, 1);
    }
}

#[test]
fn application_wake_refreshes_its_deadline_without_commands() {
    use core::cell::Cell;
    struct Timer<'a> {
        network: &'a support::Network,
        armed: &'a Cell<Option<Instant>>,
    }
    impl Clock for Timer<'_> {
        fn now(&self) -> Instant {
            self.network.now()
        }
        async fn sleep_until(&self, deadline: Instant) {
            self.armed.set(Some(deadline));
            self.network.sleep_until(deadline).await;
        }
    }
    struct App<'a> {
        ready: &'a Cell<bool>,
        deadline: Option<Instant>,
        fired: &'a Cell<bool>,
        waker: &'a RefCell<Option<Waker>>,
    }
    impl mai_coap::endpoint::Application<128> for App<'_> {
        fn handle(
            &mut self,
            _: Request<'_>,
            _: &mut ResponseWriter<'_, 128>,
        ) -> Result<Disposition, Code> {
            Err(Code::NOT_FOUND)
        }
        fn recognizes(&self, _: mai_coap::codec::OptionNumber) -> bool {
            false
        }
        fn poll(&mut self, now: Instant, cx: &mut Context<'_>) {
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            if self.ready.replace(false) {
                self.deadline = Some(now.after(10));
            }
            if self.deadline.is_some_and(|deadline| deadline <= now) {
                self.deadline = None;
                self.fired.set(true);
            }
        }
        fn deadline(&self) -> Option<Instant> {
            self.deadline
        }
    }
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
    let clock = support::Network::default();
    let mut socket = clock.socket("192.0.2.2:5683");
    let armed = Cell::new(None);
    let timer = Timer {
        network: &clock,
        armed: &armed,
    };
    let ready = Cell::new(false);
    let fired = Cell::new(false);
    let waker = RefCell::new(None);
    let mut app = App {
        ready: &ready,
        deadline: None,
        fired: &fired,
        waker: &waker,
    };
    let mut cx = Context::from_waker(Waker::noop());
    let mut driver = core::pin::pin!(endpoint.run(&mut socket, &timer, &mut app, &AllowAll));
    assert!(driver.as_mut().poll(&mut cx).is_pending());
    ready.set(true);
    waker.borrow_mut().take().unwrap().wake();
    assert!(driver.as_mut().poll(&mut cx).is_pending());
    assert!(
        !ready.get(),
        "an application wake must poll the application"
    );
    assert_eq!(armed.get(), Some(Instant(10)));
    clock.advance(9);
    assert!(driver.as_mut().poll(&mut cx).is_pending());
    assert!(!fired.get());
    clock.advance(1);
    assert!(driver.as_mut().poll(&mut cx).is_pending());
    assert!(
        fired.get(),
        "the wait must use the new application deadline"
    );
    assert!(clock.sent().is_empty());
}
