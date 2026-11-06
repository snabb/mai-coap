//! One run: the endpoint driver and the requests, raced on a single thread.
use crate::{
    args::Args,
    credentials::SERVER,
    exit::{self, Failure},
    output::{self, BodySink, Output},
    target::Route,
};
use async_io::Timer;
use futures_lite::{
    StreamExt,
    future::{self, block_on, race},
};
use mai_coap::{
    Error,
    codec::{Code, MessageView, OptionNumber},
    endpoint::{
        Client, DefaultEndpoint, DefaultShared, Protection, Request, RequestBuilder, ResponseWriter,
    },
    security::ProtectedOnly,
    time::StdClock,
    transport::linux::StdTransport,
};
use std::time::Duration;

/// How long to wait for the Observe=1 exchange before exiting anyway.
const DEREGISTER_WAIT: Duration = Duration::from_secs(5);

/// Everything a run needs, resolved before the driver starts.
pub struct Plan<'a> {
    pub args: &'a Args,
    pub route: Route,
    pub body: Vec<u8>,
    pub secured: bool,
}

type Handle<'a> = Client<'a, { mai_coap::DEFAULT_DATAGRAM }, { mai_coap::DEFAULT_OUTBOUND }>;
type Builder<'a> =
    RequestBuilder<'a, { mai_coap::DEFAULT_DATAGRAM }, { mai_coap::DEFAULT_OUTBOUND }>;

fn status(args: &Args, line: &str) {
    if !args.quiet {
        eprintln!("{line}");
    }
}

fn verbose(args: &Args, remote: std::net::SocketAddr, message: MessageView<'_>) {
    if args.verbose > 0 {
        for line in output::details(remote, message) {
            eprintln!("{line}");
        }
    }
}

fn client<'a>(plan: &Plan<'_>, shared: &'a DefaultShared) -> Handle<'a> {
    let mut client = shared.handle().client(plan.route.target);
    if plan.route.proxied {
        client = client.through_proxy();
    }
    if plan.secured {
        client = client
            .peer(SERVER)
            .combined_edhoc(!plan.args.sequential_edhoc);
    }
    client
}

fn build<'a>(plan: &Plan<'_>, client: Handle<'a>) -> Result<Builder<'a>, Error> {
    let args = plan.args;
    let mut request = client
        .request(args.method, &plan.route.uri)?
        .confirmable(!args.non);
    if let Some(format) = args.content_format {
        request = request.uint_option(OptionNumber::CONTENT_FORMAT, format.into())?;
    }
    if let Some(format) = args.accept {
        request = request.uint_option(OptionNumber::ACCEPT, format.into())?;
    }
    for option in &args.options {
        request = request.option(option.number, &option.value)?;
    }
    if let Some(szx) = args.szx() {
        request = request.block_size(szx)?;
    }
    if let Some(block) = args.block
        && block.number != 0
    {
        request = request.resume_block(block.number)?;
    }
    Ok(request)
}

/// Writes off the driver's thread, so a stalled pipe can't stop retransmissions and ACKs.
async fn write(output: Output, body: Vec<u8>) -> (Output, Result<(), Failure>) {
    blocking::unblock(move || {
        let mut output = output;
        let result = output.write(&body);
        (output, result)
    })
    .await
}

/// Reports a response and writes its payload. Returns the exit code it implies.
async fn deliver(
    plan: &Plan<'_>,
    output: Output,
    remote: std::net::SocketAddr,
    message: MessageView<'_>,
    body: Vec<u8>,
) -> (Output, Result<u8, Failure>) {
    verbose(plan.args, remote, message);
    let success = message.code().is_success();
    let code = if success {
        exit::SUCCESS
    } else {
        status(plan.args, &output::status_line(message.code()));
        exit::ERROR_RESPONSE
    };
    let body = if success {
        body
    } else {
        // A diagnostic payload is in the reply; the sink holds no body.
        message.payload().to_vec()
    };
    let (output, result) = write(output, body).await;
    let result = match result {
        // The response code stays the outcome even if its diagnostic can't be shown.
        Err(failure) if !success => {
            status(plan.args, &failure.message);
            Ok(code)
        }
        other => other.map(|()| code),
    };
    (output, result)
}

async fn single(plan: &Plan<'_>, shared: &DefaultShared) -> Result<u8, Failure> {
    let mut output = Output::new(plan.args.output.as_deref(), plan.args.newline);
    let mut outcome = exit::SUCCESS;
    for repeat in 0..plan.args.repeat {
        if repeat > 0 {
            Timer::after(Duration::from_secs(1)).await;
        }
        let mut sink = BodySink::new(plan.args.max_size);
        let transfer = build(plan, client(plan, shared))?
            .transfer(&plan.body, &mut sink)
            .await?;
        let message = transfer.reply.message()?;
        let (returned, result) =
            deliver(plan, output, transfer.reply.remote, message, sink.bytes).await;
        output = returned;
        outcome = outcome.max(result?);
    }
    Ok(outcome)
}

enum Step<T> {
    Notification(T),
    Stop(u8),
}

async fn observe(plan: &Plan<'_>, shared: &DefaultShared) -> Result<u8, Failure> {
    if !matches!(plan.args.method, Code::GET | Code::FETCH) {
        return Err(Failure::local("only GET and FETCH can observe a resource"));
    }
    if !plan.body.is_empty() && plan.args.method != Code::FETCH {
        return Err(Failure::local("only FETCH can observe with a payload"));
    }
    let mut output = Output::new(plan.args.output.as_deref(), plan.args.newline);
    output.newline |= output.to_terminal();
    let mut signals =
        async_signal::Signals::new([async_signal::Signal::Int, async_signal::Signal::Term])?;
    let mut request = build(plan, client(plan, shared))?;
    if !plan.body.is_empty() {
        request = request.payload(&plan.body)?;
    }
    let mut observation = request.observe()?;
    let duration = plan.args.subscribe.map(Duration::from_secs);
    let expiry = duration.map(|duration| std::time::Instant::now() + duration);
    let mut first = true;
    let outcome = loop {
        let mut sink = BodySink::new(plan.args.max_size);
        let step = race(
            async { Step::Notification(observation.next_into(&mut sink).await) },
            race(
                async {
                    let _ = signals.next().await;
                    Step::Stop(exit::INTERRUPTED)
                },
                async {
                    match expiry {
                        Some(expiry) => {
                            Timer::at(expiry).await;
                            Step::Stop(exit::SUCCESS)
                        }
                        None => future::pending().await,
                    }
                },
            ),
        )
        .await;
        let result = match step {
            Step::Stop(code) => break Ok(code),
            Step::Notification(None) => break Ok(exit::SUCCESS),
            // OBS-6: an inconsistent notification is discarded; the next one is complete.
            Step::Notification(Some(Err(Error::RepresentationChanged))) => continue,
            Step::Notification(Some(result)) => result,
        };
        let transfer = match result {
            Ok(transfer) => transfer,
            Err(error) => break Err(Failure::from(error)),
        };
        let message = transfer.reply.message()?;
        if first
            && message.code().is_success()
            && message.option(OptionNumber::OBSERVE).is_none()
            && message.option(OptionNumber::BLOCK2).is_none()
        {
            status(plan.args, "the server did not accept the observation");
        }
        first = false;
        let (returned, delivered) =
            deliver(plan, output, transfer.reply.remote, message, sink.bytes).await;
        output = returned;
        match delivered {
            Ok(exit::SUCCESS) => {}
            other => break other,
        }
    };
    let deregistered = race(
        async { observation.deregister().await.map(|_| ()) },
        async {
            Timer::after(DEREGISTER_WAIT).await;
            Err(Error::Timeout)
        },
    )
    .await;
    if let Err(error) = deregistered
        && plan.args.verbose > 0
    {
        eprintln!("deregistering: {error}");
    }
    outcome
}

/// Runs the plan to completion, returning the process exit code.
pub fn execute<P: Protection>(plan: &Plan<'_>, protection: P) -> Result<u8, Failure> {
    // RFC 8132 section 2.3.1: "A FETCH request MUST include a Content-Format option".
    if plan.args.method == Code::FETCH && plan.args.content_format.is_none() {
        return Err(Failure::local("FETCH needs a Content-Format; use -t"));
    }
    let shared = DefaultShared::new();
    let mut endpoint = DefaultEndpoint::new(&shared, protection)?;
    let mut socket = StdTransport::bind(plan.route.bind)
        .map_err(|e| Failure::local(format!("binding {}: {e}", plan.route.bind)))?;
    let clock = StdClock::default();
    let mut application = |_: Request<'_>, _: &mut ResponseWriter<'_>| Err(Code::NOT_FOUND);
    let driver = endpoint.run(&mut socket, &clock, &mut application, &ProtectedOnly);
    let work = async {
        let work = async {
            if plan.args.observing() {
                observe(plan, &shared).await
            } else {
                single(plan, &shared).await
            }
        };
        match plan.args.timeout {
            Some(seconds) if !plan.args.observing() => {
                race(work, async {
                    Timer::after(Duration::from_secs(seconds)).await;
                    Err(Failure::network(format!(
                        "no result within {seconds} seconds"
                    )))
                })
                .await
            }
            _ => work.await,
        }
    };
    block_on(race(
        async {
            match driver.await {
                Ok(()) => Err(Failure::network("the endpoint driver stopped")),
                Err(error) => Err(Failure::network(error.to_string())),
            }
        },
        work,
    ))
}
