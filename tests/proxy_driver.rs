//! PRX-1: forwarding completion must resume the receiving endpoint driver.
#![cfg(feature = "proxy")]
mod support;

use core::{future::Future, pin::Pin, task::Context};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    proxy::{ForwardProxy, Routing},
    security::ProtectedOnly,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Wrapped<A>(A);
impl<A: mai_coap::endpoint::Application<256>> mai_coap::endpoint::Application<256> for Wrapped<A> {
    mai_coap::delegate_application!(0, 256);
}
struct Route;
impl Routing for Route {
    fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
        true
    }
}
struct Wake(AtomicUsize);
impl std::task::Wake for Wake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn drive_to_idle(mut driver: Pin<&mut impl Future>, wake: &Wake, cx: &mut Context<'_>) -> usize {
    let mut wakes = 0;
    for _ in 0..20 {
        wake.0.store(0, Ordering::SeqCst);
        assert!(driver.as_mut().poll(cx).is_pending());
        let count = wake.0.load(Ordering::SeqCst);
        wakes += count;
        if count == 0 {
            return wakes;
        }
    }
    panic!("drivers did not become idle within 20 wake-driven polls");
}

fn check<Incoming: mai_coap::endpoint::role::Role, Outgoing: mai_coap::endpoint::role::Role>(
    separate: bool,
) {
    let network = support::Network::default();
    let incoming = Shared::<256, 3>::new();
    let outgoing = Shared::<256, 3>::new();
    let mut inbound = Endpoint::<
        _,
        256,
        3,
        8,
        8,
        8,
        16,
        3,
        3,
        8,
        40,
        mai_coap::InlineStorage<256, 40>,
        Incoming,
    >::new_with_role(&incoming, Unsecured(rand::rng()))
    .unwrap();
    let mut outbound = Endpoint::<
        _,
        256,
        3,
        8,
        8,
        8,
        16,
        3,
        3,
        8,
        40,
        mai_coap::InlineStorage<256, 40>,
        Outgoing,
    >::new_with_role(&outgoing, Unsecured(rand::rng()))
    .unwrap();
    let mut a = network.socket("192.0.2.2:5683");
    let mut b = network.socket("192.0.2.3:5683");
    let requester = "192.0.2.1:5683".parse().unwrap();
    let origin = "192.0.2.9:5683".parse().unwrap();
    let proxy = ForwardProxy::<_, _, 256, 3, 2>::with_outbound(
        |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND),
        Route,
        incoming.handle(),
        if separate {
            outgoing.handle()
        } else {
            incoming.handle()
        },
    )
    .unwrap();
    let mut proxy = Wrapped(proxy);
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    let mut bytes = [0; 256];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a").unwrap();
    builder
        .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = builder.finish(&[]).unwrap();
    network.inject(requester, a.local, &bytes[..n]);
    let wake = Arc::new(Wake(AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let drivers = futures_lite::future::race(
        inbound.run(&mut a, &network, &mut proxy, &ProtectedOnly),
        outbound.run(&mut b, &network, &mut unused, &ProtectedOnly),
    );
    let mut drivers = core::pin::pin!(drivers);
    drive_to_idle(drivers.as_mut(), &wake, &mut cx);
    let upstream = network.sent().into_iter().find(|p| p.to == origin).unwrap();
    let request = MessageView::parse(&upstream.bytes).unwrap();
    let mut response = Response::<256>::new(Code::CONTENT);
    response.set_payload(b"origin").unwrap();
    let n = response
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            request.message_id(),
            request.token(),
        )
        .unwrap();
    network.inject(origin, upstream.from, &bytes[..n]);
    assert!(
        drive_to_idle(drivers.as_mut(), &wake, &mut cx) > 0,
        "completion must wake the task"
    );
    let sent = network.sent();
    let relayed = sent
        .iter()
        .find(|p| {
            p.to == requester && MessageView::parse(&p.bytes).unwrap().code() == Code::CONTENT
        })
        .expect("completed upstream response must be relayed without advancing the clock");
    let response = MessageView::parse(&relayed.bytes).unwrap();
    assert_eq!(response.token(), b"a");
    assert_eq!(response.payload(), b"origin");
    assert_eq!(relayed.at, mai_coap::time::Instant(0));
}

#[test]
fn shared_endpoint_relays_without_timer() {
    check::<mai_coap::endpoint::role::Combined, mai_coap::endpoint::role::Combined>(false);
}

#[test]
fn separate_endpoint_relays_without_timer() {
    check::<mai_coap::endpoint::role::Combined, mai_coap::endpoint::role::Combined>(true);
}

#[test]
fn separate_server_and_client_roles_relay_without_timer() {
    check::<mai_coap::endpoint::role::Server, mai_coap::endpoint::role::Client>(true);
}

#[derive(Default)]
struct TimerState {
    now: mai_coap::time::Instant,
    next: usize,
    waiters: Vec<(usize, mai_coap::time::Instant, std::task::Waker)>,
}
#[derive(Clone, Default)]
// Network::advance also wakes socket waiters, which could hide a lost completion wake.
struct Timer(std::rc::Rc<std::cell::RefCell<TimerState>>);
struct TimerRegistration {
    timer: Timer,
    id: usize,
}
impl Drop for TimerRegistration {
    fn drop(&mut self) {
        self.timer.0.borrow_mut().waiters.retain(|w| w.0 != self.id);
    }
}
impl mai_coap::time::Clock for Timer {
    fn now(&self) -> mai_coap::time::Instant {
        self.0.borrow().now
    }
    async fn sleep_until(&self, deadline: mai_coap::time::Instant) {
        let id = {
            let mut state = self.0.borrow_mut();
            state.next += 1;
            state.next
        };
        let _registration = TimerRegistration {
            timer: self.clone(),
            id,
        };
        core::future::poll_fn(|cx| {
            let mut state = self.0.borrow_mut();
            if state.now >= deadline {
                return core::task::Poll::Ready(());
            }
            if let Some(waiter) = state.waiters.iter_mut().find(|w| w.0 == id) {
                waiter.2 = cx.waker().clone();
            } else {
                state.waiters.push((id, deadline, cx.waker().clone()));
            }
            core::task::Poll::Pending
        })
        .await;
    }
}
impl Timer {
    fn next(&self) -> mai_coap::time::Instant {
        self.0.borrow().waiters.iter().map(|w| w.1).min().unwrap()
    }
    fn advance_to(&self, now: mai_coap::time::Instant) -> usize {
        let due = {
            let mut state = self.0.borrow_mut();
            assert!(now >= state.now);
            state.now = now;
            let mut due = Vec::new();
            state.waiters.retain(|(_, deadline, waker)| {
                if *deadline <= now {
                    due.push(waker.clone());
                    false
                } else {
                    true
                }
            });
            due
        };
        let count = due.len();
        for waker in due {
            waker.wake();
        }
        count
    }
}

fn drive_ready(
    mut incoming: Pin<&mut (impl Future + ?Sized)>,
    mut outgoing: Pin<&mut (impl Future + ?Sized)>,
    wakes: &[Arc<Wake>; 2],
    contexts: &mut [Context<'_>; 2],
) {
    // Polling both drivers unconditionally would hide a missing cross-driver wake.
    for _ in 0..40 {
        let mut polled = false;
        if wakes[0].0.swap(0, Ordering::SeqCst) != 0 {
            assert!(incoming.as_mut().poll(&mut contexts[0]).is_pending());
            polled = true;
        }
        if wakes[1].0.swap(0, Ordering::SeqCst) != 0 {
            assert!(outgoing.as_mut().poll(&mut contexts[1]).is_pending());
            polled = true;
        }
        if !polled {
            return;
        }
    }
    panic!("drivers did not become idle within 40 scheduled polls");
}

fn silent_origin_timeout(parameters: mai_coap::messaging::TransmissionParameters, joined: bool) {
    use mai_coap::{
        endpoint::role,
        messaging::TransmissionParameters,
        time::{Clock, Instant},
    };
    use rand::SeedableRng;
    struct TimeoutRoute(TransmissionParameters);
    impl Routing for TimeoutRoute {
        fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
            true
        }
        fn parameters(&self, _: core::net::SocketAddr) -> TransmissionParameters {
            self.0
        }
    }
    let network = support::Network::default();
    let timer = Timer::default();
    let incoming = Shared::<256, 1>::new();
    let outgoing = Shared::<256, 1>::new();
    type Driver<'a, R> = Endpoint<
        'a,
        Unsecured<rand::rngs::StdRng>,
        256,
        1,
        4,
        0,
        1,
        2,
        1,
        1,
        0,
        4,
        mai_coap::InlineStorage<256, 4>,
        R,
    >;
    let mut inbound = Driver::<role::Server>::new_with_role(
        &incoming,
        Unsecured(rand::rngs::StdRng::seed_from_u64(1)),
    )
    .unwrap();
    let mut outbound = Driver::<role::Client>::new_with_role(
        &outgoing,
        Unsecured(rand::rngs::StdRng::seed_from_u64(2)),
    )
    .unwrap();
    let mut a = network.socket("192.0.2.2:5683");
    let mut b = network.socket("192.0.2.3:5683");
    let requester = "192.0.2.1:5683".parse().unwrap();
    let receiving = a.local;
    let origin = "192.0.2.9:5683".parse().unwrap();
    let mut proxy = ForwardProxy::<_, _, 256, 1, 1>::with_outbound(
        |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND),
        TimeoutRoute(parameters),
        incoming.handle(),
        outgoing.handle(),
    )
    .unwrap();
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    let mut bytes = [0; 256];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a").unwrap();
    builder
        .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = builder.finish(&[]).unwrap();
    network.inject(requester, receiving, &bytes[..n]);
    let wakes = [
        Arc::new(Wake(AtomicUsize::new(1))),
        Arc::new(Wake(AtomicUsize::new(1))),
    ];
    let wakers = wakes
        .each_ref()
        .map(|wake| std::task::Waker::from(wake.clone()));
    let mut contexts = wakers.each_ref().map(Context::from_waker);
    let inbound = inbound.run(&mut a, &timer, &mut proxy, &ProtectedOnly);
    let outbound = outbound.run(&mut b, &timer, &mut unused, &ProtectedOnly);
    type Task<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;
    let (mut inbound, mut outbound): (Task<'_>, Task<'_>) = if joined {
        (
            Box::pin(async {
                let result = futures_lite::future::zip(inbound, outbound).await;
                panic!("joined drivers stopped: {result:?}");
            }),
            Box::pin(core::future::pending()),
        )
    } else {
        (
            Box::pin(async {
                let result = inbound.await;
                panic!("receiving driver stopped: {result:?}");
            }),
            Box::pin(async {
                let result = outbound.await;
                panic!("outbound driver stopped: {result:?}");
            }),
        )
    };
    drive_ready(inbound.as_mut(), outbound.as_mut(), &wakes, &mut contexts);
    let sent = network.sent();
    let ack = sent.iter().find(|p| p.to == requester).unwrap();
    let ack = MessageView::parse(&ack.bytes).unwrap();
    assert_eq!(ack.message_type(), MessageType::Acknowledgement);
    assert_eq!(ack.code(), Code::EMPTY);
    assert_eq!(ack.message_id(), 1);
    assert!(sent.iter().any(|p| p.to == origin));

    let mut timeout = None;
    for _ in 0..10 {
        let next = timer.next();
        assert!(next <= Instant(parameters.max_transmit_wait()));
        assert_eq!(
            timer.advance_to(next),
            1,
            "only the upstream timer should expire"
        );
        if !joined {
            assert_eq!(
                wakes[0].0.load(Ordering::SeqCst),
                0,
                "the receiving timer is not due"
            );
        }
        assert!(wakes[usize::from(!joined)].0.load(Ordering::SeqCst) > 0);
        drive_ready(inbound.as_mut(), outbound.as_mut(), &wakes, &mut contexts);
        timeout = network.sent().into_iter().find(|p| {
            p.to == requester
                && MessageView::parse(&p.bytes).unwrap().code() == Code::GATEWAY_TIMEOUT
        });
        if timeout.is_some() {
            break;
        }
    }
    let timeout = timeout.expect("silent origin must produce a separate 5.04 on timer wake alone");
    assert_eq!(
        network.sent().iter().filter(|p| p.to == origin).count(),
        usize::from(parameters.max_retransmit) + 1,
    );
    let response = MessageView::parse(&timeout.bytes).unwrap();
    assert_eq!(response.message_type(), MessageType::Confirmable);
    assert_eq!(response.token(), b"a");
    if parameters.max_retransmit == 0 {
        assert_eq!(timer.now(), Instant(100));
    }
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        response.message_id(),
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    network.inject(requester, receiving, &bytes[..n]);
    wakes[0].0.fetch_add(1, Ordering::SeqCst);
    drive_ready(inbound.as_mut(), outbound.as_mut(), &wakes, &mut contexts);

    let previous = network.sent().len();
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 2, b"b").unwrap();
    builder
        .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = builder.finish(&[]).unwrap();
    network.inject(requester, receiving, &bytes[..n]);
    wakes[0].0.fetch_add(1, Ordering::SeqCst);
    drive_ready(inbound.as_mut(), outbound.as_mut(), &wakes, &mut contexts);
    let forwarded = network
        .sent()
        .into_iter()
        .skip(previous)
        .find(|p| p.to == origin)
        .expect("timeout must release the sole forwarding and upstream command slots");
    let request = MessageView::parse(&forwarded.bytes).unwrap();
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap()
    .finish(b"recovered")
    .unwrap();
    network.inject(origin, forwarded.from, &bytes[..n]);
    wakes[usize::from(!joined)].0.fetch_add(1, Ordering::SeqCst);
    drive_ready(inbound.as_mut(), outbound.as_mut(), &wakes, &mut contexts);
    let recovered = network
        .sent()
        .into_iter()
        .find(|p| {
            p.to == requester && MessageView::parse(&p.bytes).unwrap().code() == Code::CONTENT
        })
        .expect("forwarding after timeout must deliver the origin response");
    let recovered = MessageView::parse(&recovered.bytes).unwrap();
    assert_eq!(recovered.token(), b"b");
    assert_eq!(recovered.payload(), b"recovered");
}

#[test]
fn separate_driver_timeout_returns_504_without_inbound_traffic() {
    silent_origin_timeout(
        mai_coap::messaging::TransmissionParameters::default()
            .with_ack_timeout_ms(100)
            .with_ack_random_factor(1000)
            .with_max_retransmit(0)
            .with_max_latency_ms(1000),
        false,
    );
}

#[test]
fn separate_driver_default_retries_return_504_without_inbound_traffic() {
    silent_origin_timeout(
        mai_coap::messaging::TransmissionParameters::default(),
        false,
    );
}

#[test]
fn joined_driver_timeout_returns_504_without_inbound_traffic() {
    silent_origin_timeout(
        mai_coap::messaging::TransmissionParameters::default()
            .with_ack_timeout_ms(100)
            .with_ack_random_factor(1000)
            .with_max_retransmit(0)
            .with_max_latency_ms(1000),
        true,
    );
}

#[test]
fn joined_driver_default_retries_return_504_without_inbound_traffic() {
    silent_origin_timeout(mai_coap::messaging::TransmissionParameters::default(), true);
}
