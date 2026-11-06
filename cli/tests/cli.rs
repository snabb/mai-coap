//! Runs the built binary against loopback servers using the library's server role.
use futures_lite::future::block_on;
use mai_coap::{
    codec::{Code, ContentFormat, OptionNumber},
    crypto::SoftwareCrypto,
    edhoc::{Identity, TrustedPeer, endpoint::Edhoc},
    endpoint::{
        DefaultEndpoint, DefaultShared, Disposition, Protection, Request, ResponseWriter, Unsecured,
    },
    observe::Settings,
    proxy::{ForwardProxy, Routing},
    security::{PeerId, Policy, ProtectedOnly, PublicPaths},
    server::{DefaultRouter, SliceBody},
    time::StdClock,
    transport::linux::StdTransport,
};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const PUBLIC: PublicPaths<'static> = PublicPaths(&[
    (Code::GET, "/hello"),
    (Code::GET, "/large"),
    (Code::GET, "/clock"),
    (Code::GET, "/forbidden"),
    (Code::GET, "/binary"),
    (Code::GET, "/echo"),
    (Code::POST, "/echo"),
    (Code::PUT, "/echo"),
    (Code::DELETE, "/echo"),
    (Code::FETCH, "/echo"),
    (Code::PATCH, "/echo"),
    (Code::IPATCH, "/echo"),
    (Code::PUT, "/upload"),
]);

fn large() -> Vec<u8> {
    (0..3000).map(|i| (i % 251) as u8).collect()
}

/// `method|host|port|format|accept|custom|body`, so tests see what reached the server.
fn describe(request: Request<'_>) -> Vec<u8> {
    let message = request.message;
    let uint = |number| {
        message
            .option(number)
            .map_or("-".to_owned(), |o| o.uint().unwrap().to_string())
    };
    let host = message
        .option(OptionNumber::URI_HOST)
        .map_or("-".to_owned(), |o| {
            String::from_utf8_lossy(o.value).into_owned()
        });
    // An option the endpoint recognizes; it discards unknown elective ones (MSG-5).
    let custom = message
        .option(OptionNumber::ETAG)
        .map_or("-".to_owned(), |o| {
            String::from_utf8_lossy(o.value).into_owned()
        });
    let mut text = format!(
        "{}|{host}|{}|{}|{}|{custom}|",
        message.code().0,
        uint(OptionNumber::URI_PORT),
        uint(OptionNumber::CONTENT_FORMAT),
        uint(OptionNumber::ACCEPT),
    )
    .into_bytes();
    text.extend_from_slice(request.payload());
    text
}

fn spawn_server<P, F, G>(make: F, policy: G) -> SocketAddr
where
    P: Protection + 'static,
    F: FnOnce() -> P + Send + 'static,
    G: Policy + Send + Sync + 'static,
{
    spawn_server_at("127.0.0.1:0".parse().unwrap(), make, policy)
}

/// Serves test resources forever on a detached thread; the process exit ends it.
fn spawn_server_at<P, F, G>(bind: SocketAddr, make: F, policy: G) -> SocketAddr
where
    P: Protection + 'static,
    F: FnOnce() -> P + Send + 'static,
    G: Policy + Send + Sync + 'static,
{
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_payload(b"world")?;
            Ok(Disposition::Complete)
        };
        let mut echo = |request: Request<'_>, response: &mut ResponseWriter<'_>| {
            if request.message.code() != Code::FETCH && request.message.code() != Code::GET {
                response.set_code(Code::CHANGED);
            }
            response.set_payload(&describe(request))?;
            Ok(Disposition::Complete)
        };
        let mut forbidden = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_code(Code::FORBIDDEN);
            response.set_payload(b"not for you")?;
            Ok(Disposition::Complete)
        };
        let mut binary = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_payload(b"\x1b[2J\xff\x00")?;
            Ok(Disposition::Complete)
        };
        let mut upload = |request: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_code(Code::CHANGED);
            let sum: u64 = request.payload().iter().map(|b| u64::from(*b)).sum();
            let text = format!("{} {sum}", request.payload().len());
            response.set_payload(text.as_bytes())?;
            Ok(Disposition::Complete)
        };
        let mut counter = 0u32;
        let mut clock = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            counter += 1;
            response.set_payload(counter.to_string().as_bytes())?;
            Ok(Disposition::Complete)
        };
        let content = large();
        let mut representation = {
            let mut body = SliceBody::new(&content, ContentFormat::OCTET_STREAM);
            body.etag = b"fixed";
            body.max_age = 60;
            body
        };
        let mut router = DefaultRouter::new(&policy);
        router.route("/hello", &[Code::GET], &mut hello).unwrap();
        router
            .route(
                "/echo",
                &[
                    Code::GET,
                    Code::POST,
                    Code::PUT,
                    Code::DELETE,
                    Code::FETCH,
                    Code::PATCH,
                    Code::IPATCH,
                ],
                &mut echo,
            )
            .unwrap();
        router
            .route("/forbidden", &[Code::GET], &mut forbidden)
            .unwrap();
        router.route("/binary", &[Code::GET], &mut binary).unwrap();
        router
            .buffered_upload("/upload", &[Code::PUT], &mut upload)
            .unwrap();
        router.route("/clock", &[Code::GET], &mut clock).unwrap();
        router
            .observable(
                "/clock",
                Settings::new(1)
                    .with_minimum_ms(50)
                    .with_maximum_ms(200)
                    .with_confirmable_ms(1000),
            )
            .unwrap();
        router
            .representation("/large", &mut representation)
            .unwrap();
        let mut socket = StdTransport::bind(bind).unwrap();
        sender.send(socket.local_addr().unwrap()).unwrap();
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, make()).unwrap();
        block_on(endpoint.run(&mut socket, &StdClock::default(), &mut router, &policy)).unwrap();
    });
    receiver.recv().unwrap()
}

fn public_server() -> SocketAddr {
    spawn_server(|| Unsecured(rand::rng()), PUBLIC)
}

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mai-coap-cli-test-{name}-{}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mai-coap"))
}

/// Runs to completion with a deadline, so a hang fails instead of stalling the suite.
fn run(arguments: &[&str]) -> Output {
    run_with_stdin(arguments, b"")
}

fn run_with_stdin(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = binary()
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    wait(child)
}

fn wait(mut child: std::process::Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the CLI did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[track_caller]
fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout {:?}, stderr {}",
        String::from_utf8_lossy(&output.stdout),
        stderr(output)
    );
}

fn uri(server: SocketAddr, path: &str) -> String {
    format!("coap://{server}{path}")
}

#[test]
fn get_writes_only_the_payload_to_stdout() {
    let server = public_server();
    let output = run(&[&uri(server, "/hello")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"world");
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    let output = run(&["-w", &uri(server, "/hello")]);
    assert_eq!(output.stdout, b"world\n");
}

#[test]
fn error_responses_exit_1_with_status_on_stderr_and_diagnostic_on_stdout() {
    let server = public_server();
    let output = run(&[&uri(server, "/forbidden")]);
    assert_code(&output, 1);
    assert_eq!(output.stdout, b"not for you");
    assert!(stderr(&output).contains("4.03 Forbidden"));
    let output = run(&["-q", &uri(server, "/forbidden")]);
    assert_code(&output, 1);
    assert!(output.stderr.is_empty());
    let output = run(&["-m", "delete", &uri(server, "/hello")]);
    assert_code(&output, 1);
    assert!(stderr(&output).contains("4."));
}

#[test]
fn every_method_reaches_the_server_with_its_body_and_options() {
    let server = public_server();
    let target = uri(server, "/echo");
    for (method, code) in [
        ("post", 2),
        ("PUT", 3),
        ("delete", 4),
        ("patch", 6),
        ("iPATCH", 7),
        ("2", 2),
    ] {
        let output = run(&[
            "-m", method, "-t", "json", "-A", "cbor", "-O", "4,tag", "-e", "a%20b", &target,
        ]);
        assert_code(&output, 0);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("{code}|-|-|50|60|tag|a b"),
            "{method}"
        );
    }
    let output = run(&["-m", "fetch", "-t", "60", "--payload", "@-", &target]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"5|-|-|60|-|-|");
}

#[test]
fn fetch_without_content_format_is_refused_locally() {
    let server = public_server();
    let output = run(&["-m", "fetch", &uri(server, "/echo")]);
    assert_code(&output, 2);
    assert!(stderr(&output).contains("Content-Format"));
}

#[test]
fn payload_sources_and_literal_at_sign() {
    let server = public_server();
    let target = uri(server, "/echo");
    let directory = Directory::new("payload");
    let file = directory.file("body");
    fs::write(&file, b"from file").unwrap();
    let file = file.to_str().unwrap();
    for (flags, expected) in [
        (vec!["-f", file], "from file"),
        (vec!["--payload", &format!("@{file}")[..]], "from file"),
        (vec!["--payload", "literal"], "literal"),
        (vec!["-e", "@literal"], "@literal"),
    ] {
        let mut arguments = vec!["-m", "post"];
        arguments.extend(&flags);
        arguments.push(&target);
        let output = run(&arguments);
        assert_code(&output, 0);
        assert!(
            String::from_utf8_lossy(&output.stdout).ends_with(&format!("|{expected}")),
            "{flags:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    for flags in [&["-f", "-"], &["--payload", "@-"]] {
        let output = run_with_stdin(
            &[&["-m", "post"], &flags[..], &[&target]].concat(),
            b"piped",
        );
        assert_code(&output, 0);
        assert!(output.stdout.ends_with(b"|piped"));
    }
    let output = run(&["-m", "post", "-f", "/no/such/file", &target]);
    assert_code(&output, 2);
}

#[test]
fn rfc_7252_authority_options_depend_on_the_destination() {
    let server = public_server();
    let port = server.port();
    let echo = |host: &str, extra: &[&str]| {
        let target = format!("coap://{host}:{port}/echo");
        let output = run(&[extra, &[&target]].concat());
        assert_code(&output, 0);
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    assert!(echo("127.0.0.1", &[]).starts_with("1|-|-|"));
    assert!(echo("localhost", &["-4"]).starts_with("1|localhost|-|"));
    assert!(echo("LOCALHOST", &["-4"]).starts_with("1|localhost|-|"));
    assert!(echo("localhost", &["-4", "-U"]).starts_with("1|-|-|"));
}

#[test]
fn block_wise_download_reassembles_at_any_size_and_can_resume() {
    let content = large();
    // A fresh server each time: its rate limit would otherwise slow these down, and a
    // dropped NON request is never retransmitted.
    for flags in [
        &[][..],
        &["-b", "64"],
        &["--payload-initial-szx", "3"],
        &["-N", "-b", "256"],
    ] {
        let target = uri(public_server(), "/large");
        let output = run(&[flags, &["-B", "50", &target]].concat());
        assert_code(&output, 0);
        assert_eq!(output.stdout, content, "{flags:?}");
    }
    let target = uri(public_server(), "/large");
    let output = run(&["-b", "2,64", &target]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, content[128..]);
}

#[test]
fn max_size_bounds_the_response() {
    let server = public_server();
    let target = uri(server, "/large");
    let output = run(&["--max-size", "100", &target]);
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    let output = run(&["--max-size", "3000", &target]);
    assert_code(&output, 0);
}

#[test]
fn block_wise_upload_delivers_the_whole_body() {
    let server = public_server();
    let target = uri(server, "/upload");
    let directory = Directory::new("upload");
    let file = directory.file("body");
    let content = large();
    let sum: u64 = content.iter().map(|b| u64::from(*b)).sum();
    fs::write(&file, &content).unwrap();
    for flags in [&[][..], &["-b", "64"]] {
        let output = run(&[
            &["-m", "put", "-f", file.to_str().unwrap()],
            flags,
            &[&target],
        ]
        .concat());
        assert_code(&output, 0);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("3000 {sum}"),
            "{flags:?}"
        );
    }
}

#[test]
fn output_file_receives_the_body_and_stdout_stays_empty() {
    let server = public_server();
    let directory = Directory::new("output");
    let file = directory.file("out");
    let output = run(&["-o", file.to_str().unwrap(), &uri(server, "/large")]);
    assert_code(&output, 0);
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&file).unwrap(), large());
    let output = run(&["-o", "-", &uri(server, "/binary")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"\x1b[2J\xff\x00");
}

#[test]
fn failed_request_leaves_an_existing_output_file_alone() {
    let directory = Directory::new("keep");
    let file = directory.file("out");
    fs::write(&file, b"precious").unwrap();
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = uri(silent.local_addr().unwrap(), "/x");
    let output = run(&["-B", "1", "-o", file.to_str().unwrap(), &target]);
    assert_code(&output, 3);
    assert_eq!(fs::read(&file).unwrap(), b"precious");
}

#[test]
fn verbose_output_describes_the_response_without_raw_bytes_or_whole_tokens() {
    let server = public_server();
    let output = run(&["-v", &uri(server, "/large")]);
    assert_code(&output, 0);
    let text = stderr(&output);
    assert!(text.contains("2.05 Content"), "{text}");
    assert!(text.contains("(8 bytes)"), "{text}");
    assert!(text.contains("ETag"), "{text}");
}

#[test]
fn repeat_sends_the_request_again() {
    let server = public_server();
    let output = run(&["-G", "2", "-w", &uri(server, "/hello")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"world\nworld\n");
}

#[test]
fn silence_and_unreachable_exit_3() {
    // Bound, then never read, so nothing answers and no ICMP error comes back.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = uri(silent.local_addr().unwrap(), "/x");
    let started = Instant::now();
    let output = run(&["-B", "1", &target]);
    assert_code(&output, 3);
    assert!(started.elapsed() < Duration::from_secs(10));
    let output = run(&["-4", "coap://no-such-host.invalid/x"]);
    assert_code(&output, 3);
}

#[test]
fn unsupported_schemes_and_bad_uris_never_send_anything() {
    for (input, expected) in [
        ("example.org/x", "use coap://example.org/x"),
        ("coaps://127.0.0.1/x", "no DTLS transport"),
        ("coap+tcp://127.0.0.1/x", "no TCP transport"),
        ("coaps+tcp://127.0.0.1/x", "no TLS transport"),
        ("coap+ws://127.0.0.1/x", "no WebSocket transport"),
        ("http://127.0.0.1/x", "unknown URI scheme"),
        ("coap://224.0.1.187/.well-known/core", "multicast"),
        ("coap://user@127.0.0.1/x", "invalid URI"),
    ] {
        let output = run(&[input]);
        assert_code(&output, 2);
        assert!(stderr(&output).contains(expected), "{}", stderr(&output));
    }
    let output = run(&["-O", "11,x", "coap://127.0.0.1/x"]);
    assert_code(&output, 2);
    assert!(stderr(&output).contains("managed"));
}

#[test]
fn cbor_payload_text_is_refused_but_files_pass() {
    let server = public_server();
    let target = uri(server, "/echo");
    let output = run(&["-m", "post", "-t", "cbor", "--payload", "{1:2}", &target]);
    assert_code(&output, 2);
    let directory = Directory::new("cbor");
    let file = directory.file("body");
    fs::write(&file, b"\xa1\x01\x02").unwrap();
    let flag = format!("@{}", file.to_str().unwrap());
    let output = run(&["-m", "post", "-t", "cbor", "--payload", &flag, &target]);
    assert_code(&output, 0);
    assert!(output.stdout.ends_with(b"\xa1\x01\x02"));
}

#[test]
fn observe_prints_notifications_until_the_duration_ends() {
    let server = public_server();
    let started = Instant::now();
    let output = run(&["-s", "1", "-w", &uri(server, "/clock")]);
    assert_code(&output, 0);
    let elapsed = started.elapsed();
    assert!(
        (Duration::from_secs(1)..Duration::from_secs(10)).contains(&elapsed),
        "{elapsed:?}"
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let values: Vec<u32> = text.lines().map(|line| line.parse().unwrap()).collect();
    assert!(values.len() >= 2, "{values:?}");
    assert!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "{values:?}"
    );
}

#[test]
fn observe_of_a_resource_without_observe_reports_and_exits() {
    let server = public_server();
    let output = run(&["--observe", &uri(server, "/hello")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"world");
    assert!(stderr(&output).contains("did not accept"));
    let output = run(&["--observe", "-m", "post", &uri(server, "/echo")]);
    assert_code(&output, 2);
}

#[test]
fn observe_ends_on_interrupt_with_code_130() {
    let server = public_server();
    let child = binary()
        .args(["--observe", "-w", &uri(server, "/clock")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let output = wait(child);
    assert_code(&output, 130);
    assert!(!output.stdout.is_empty());
}

/// Answers an observation until its deregistration arrives, as RFC 7641 section 3.6 describes:
/// the token and options repeat with Observe=1. With `flood`, it also sends enough large
/// notifications to fill a pipe. `registered` runs once, after the registration is answered.
fn answer_until_deregistered(
    socket: &std::net::UdpSocket,
    flood: bool,
    mut registered: impl FnMut(),
) {
    use mai_coap::{
        codec::{MessageType, MessageView},
        endpoint::Response,
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut registration: Option<(Vec<u8>, SocketAddr)> = None;
    let mut bytes = [0; 256];
    let mut answer = [0; 1152];
    let mut sequence = 1u64;
    loop {
        assert!(Instant::now() < deadline, "no deregistration arrived");
        if let Ok((length, from)) = socket.recv_from(&mut bytes) {
            let request = MessageView::parse(&bytes[..length]).unwrap();
            let Some(observe) = request.option(OptionNumber::OBSERVE) else {
                // The empty ACK of a confirmable notification, which this peer doesn't send.
                continue;
            };
            let observe = observe.uint().unwrap();
            let mut response = Response::<1152>::new(Code::CONTENT);
            if observe == 0 {
                registration = Some((request.token().to_vec(), from));
                response
                    .uint_option(OptionNumber::OBSERVE, sequence)
                    .unwrap();
            } else {
                assert_eq!(observe, 1);
                let (token, _) = registration.as_ref().unwrap();
                assert_eq!(token, request.token());
                assert_eq!(request.option(OptionNumber::URI_PATH).unwrap().value, b"x");
            }
            let n = response
                .encode(
                    &mut answer,
                    MessageType::Acknowledgement,
                    request.message_id(),
                    request.token(),
                )
                .unwrap();
            socket.send_to(&answer[..n], from).unwrap();
            if observe == 1 {
                return;
            }
            registered();
        }
        if flood && let Some((token, from)) = &registration {
            sequence += 1;
            let mut notification = Response::<1152>::new(Code::CONTENT);
            notification
                .uint_option(OptionNumber::OBSERVE, sequence)
                .unwrap();
            notification.set_payload(&[b'x'; 1024]).unwrap();
            let n = notification
                .encode(
                    &mut answer,
                    MessageType::NonConfirmable,
                    sequence as u16,
                    token,
                )
                .unwrap();
            socket.send_to(&answer[..n], from).unwrap();
        }
    }
}

fn observe_child(arguments: &[&str], stdout: Stdio) -> std::process::Child {
    binary()
        .args(arguments)
        .stdout(stdout)
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn terminate(child: &std::process::Child) {
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn observe_deregisters_before_exiting() {
    for interrupt in [false, true] {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = uri(socket.local_addr().unwrap(), "/x");
        let arguments: &[&str] = if interrupt {
            &["--observe", &target]
        } else {
            &["-s", "1", &target]
        };
        let child = observe_child(arguments, Stdio::null());
        answer_until_deregistered(&socket, false, || {
            if interrupt {
                std::thread::sleep(Duration::from_millis(300));
                terminate(&child);
            }
        });
        assert_code(&wait(child), if interrupt { 130 } else { 0 });
    }
}

/// A FIFO without a reader blocks in open, so the first write never returns.
#[test]
fn stalled_file_output_does_not_delay_stopping_or_deregistering() {
    for interrupt in [false, true] {
        let directory = Directory::new("stalled-file");
        let fifo = directory.file("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = uri(socket.local_addr().unwrap(), "/x");
        let fifo = fifo.to_str().unwrap();
        let arguments: &[&str] = if interrupt {
            &["--observe", "-o", fifo, &target]
        } else {
            &["-s", "1", "-o", fifo, &target]
        };
        let started = Instant::now();
        let child = observe_child(arguments, Stdio::null());
        answer_until_deregistered(&socket, false, || {
            if interrupt {
                std::thread::sleep(Duration::from_millis(300));
                terminate(&child);
            }
        });
        let output = wait(child);
        assert_code(&output, if interrupt { 130 } else { 0 });
        assert!(started.elapsed() < Duration::from_secs(15));
    }
}

/// Nothing reads this pipe until the process has exited.
#[test]
fn full_stdout_pipe_does_not_delay_stopping_or_deregistering() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = uri(socket.local_addr().unwrap(), "/x");
    let started = Instant::now();
    let child = observe_child(&["-s", "2", &target], Stdio::piped());
    answer_until_deregistered(&socket, true, || {});
    let output = wait(child);
    assert_code(&output, 0);
    assert!(started.elapsed() < Duration::from_secs(15));
    // The pipe really did fill, or this test proves nothing.
    assert!(output.stdout.len() >= 16 * 1024, "{}", output.stdout.len());
}

fn link_local_address() -> Option<(std::net::Ipv6Addr, String, u32)> {
    nix::ifaddrs::getifaddrs().ok()?.find_map(|interface| {
        let address = interface.address?.as_sockaddr_in6()?.ip();
        let index = nix::net::if_::if_nametoindex(interface.interface_name.as_str()).ok()?;
        address
            .is_unicast_link_local()
            .then_some((address, interface.interface_name, index))
    })
}

/// Needs an interface with a link-local address. Unit tests cover the ordering without one.
#[test]
fn link_local_destinations_and_proxies_use_their_zone() {
    let Some((address, name, index)) = link_local_address() else {
        eprintln!("skipped: no interface has a link-local address");
        return;
    };
    let scoped = |port| SocketAddr::V6(std::net::SocketAddrV6::new(address, port, 0, index));
    let server = spawn_server_at(scoped(0), || Unsecured(rand::rng()), PUBLIC);
    let (port, hello) = (server.port(), "/hello");

    for zone in [name.as_str(), &index.to_string()] {
        let target = format!("coap://[{address}%25{zone}]:{port}{hello}");
        let output = run(&[&target]);
        assert_code(&output, 0);
        assert_eq!(output.stdout, b"world", "{zone}");
    }
    let target = format!("coap://[{address}%25{name}]:{port}/large");
    let output = run(&[&target]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, large());

    let proxy = spawn_proxy_at(scoped(0), scoped(port));
    let flag = format!("coap://[{address}%25{name}]:{}", proxy.port());
    let origin = format!("coap://[{address}]:{port}{hello}");
    let output = run(&["-P", &flag, &origin]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"world");

    let output = run(&[&format!("coap://[{address}]:{port}{hello}")]);
    assert_code(&output, 3);
    assert!(
        stderr(&output).contains("needs a zone"),
        "{}",
        stderr(&output)
    );
}

struct Allow(SocketAddr);
impl Routing for Allow {
    fn allow(&self, _: SocketAddr, host: &str, port: u16) -> bool {
        port == self.0.port() && host == self.0.ip().to_string()
    }
    fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.allow(self.0, host, port).then_some(self.0)
    }
}

fn spawn_proxy(origin: SocketAddr) -> SocketAddr {
    spawn_proxy_at("127.0.0.1:0".parse().unwrap(), origin)
}

fn spawn_proxy_at(bind: SocketAddr, origin: SocketAddr) -> SocketAddr {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut socket = StdTransport::bind(bind).unwrap();
        sender.send(socket.local_addr().unwrap()).unwrap();
        let shared = DefaultShared::new();
        let local = |_: Request<'_>, _: &mut ResponseWriter<'_>| Err(Code::NOT_FOUND);
        let mut application =
            ForwardProxy::<_, _>::new(local, Allow(origin), shared.handle()).unwrap();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
        block_on(endpoint.run(
            &mut socket,
            &StdClock::default(),
            &mut application,
            &PublicPaths(&[(Code::GET, "/")]),
        ))
        .unwrap();
    });
    receiver.recv().unwrap()
}

#[test]
fn proxy_forwards_to_the_origin_in_the_uri() {
    let origin = public_server();
    let proxy = spawn_proxy(origin);
    let flag = format!("coap://{proxy}");
    let output = run(&["-P", &flag, &uri(origin, "/hello")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, b"world");
    let output = run(&["--proxy", &flag, &uri(origin, "/large")]);
    assert_code(&output, 0);
    assert_eq!(output.stdout, large());
}

fn generate(directory: &Directory, name: &str) -> (PathBuf, PathBuf) {
    let path = directory.file(name);
    let output = run(&["--generate-identity", path.to_str().unwrap()]);
    assert_code(&output, 0);
    (
        directory.file(&format!("{name}.ccs")),
        directory.file(&format!("{name}.key")),
    )
}

fn secured_server(own: (&Path, &Path), peer: &Path) -> SocketAddr {
    let (own_ccs, own_key, peer_ccs) = (
        fs::read(own.0).unwrap(),
        fs::read(own.1).unwrap(),
        fs::read(peer).unwrap(),
    );
    spawn_server(
        move || {
            let mut crypto = SoftwareCrypto::new(rand::rng());
            let identity =
                Identity::new(&own_ccs, own_key.try_into().unwrap(), &mut crypto).unwrap();
            let mut protection = Edhoc::<_>::new(crypto, identity).unwrap();
            protection
                .trust(TrustedPeer::new(PeerId(1), &peer_ccs).unwrap())
                .unwrap();
            protection
        },
        ProtectedOnly,
    )
}

fn credential_flags<'a>(own: &'a (PathBuf, PathBuf), peer: &'a Path) -> Vec<&'a str> {
    vec![
        "--identity",
        own.0.to_str().unwrap(),
        "--key",
        own.1.to_str().unwrap(),
        "--peer",
        peer.to_str().unwrap(),
    ]
}

#[test]
fn edhoc_secures_requests_in_both_handshake_modes() {
    let directory = Directory::new("edhoc");
    let client = generate(&directory, "client");
    let server = generate(&directory, "server");
    let address = secured_server((&server.0, &server.1), &client.0);
    let flags = credential_flags(&client, &server.0);
    let hello = uri(address, "/hello");
    let echo = uri(address, "/echo");
    let big = uri(address, "/large");
    let clock = uri(address, "/clock");
    for mode in [&[][..], &["--sequential-edhoc"]] {
        let base = [&flags[..], mode].concat();
        let output = run(&[&base[..], &[&hello]].concat());
        assert_code(&output, 0);
        assert_eq!(output.stdout, b"world");
        let output = run(&[&base[..], &["-m", "post", "-e", "sealed", &echo]].concat());
        assert_code(&output, 0);
        assert!(output.stdout.ends_with(b"|sealed"));
        let output = run(&[&base[..], &[&big]].concat());
        assert_code(&output, 0);
        assert_eq!(output.stdout, large());
        let output = run(&[&base[..], &["-G", "2", "-w", &hello]].concat());
        assert_code(&output, 0);
        assert_eq!(output.stdout, b"world\nworld\n");
        let output = run(&[&base[..], &["-s", "1", "-w", &clock]].concat());
        assert_code(&output, 0);
        assert!(output.stdout.len() >= 2);
    }
}

#[test]
fn security_failures_exit_4_and_never_fall_back_to_plaintext() {
    let directory = Directory::new("failures");
    let client = generate(&directory, "client");
    let server = generate(&directory, "server");
    let other = generate(&directory, "other");
    let address = secured_server((&server.0, &server.1), &client.0);

    // Unprotected requests can't reach protected resources.
    let output = run(&[&uri(address, "/hello")]);
    assert_code(&output, 1);
    assert!(output.stdout.is_empty() || !output.stdout.starts_with(b"world"));

    // The server isn't the peer we trust.
    let flags = credential_flags(&client, &other.0);
    let output = run(&[&flags[..], &["-B", "30", &uri(address, "/hello")]].concat());
    assert_ne!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stdout.is_empty());

    // A plain server answers without protection.
    let plain = public_server();
    let flags = credential_flags(&client, &server.0);
    let output = run(&[&flags[..], &["-B", "30", &uri(plain, "/hello")]].concat());
    assert_ne!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!output.stdout.starts_with(b"world"));
}

/// The client has no resources to offer, so it must not complete handshakes for others.
#[test]
fn client_answers_inbound_edhoc_with_not_found() {
    let directory = Directory::new("responder");
    let client = generate(&directory, "client");
    let server = generate(&directory, "server");
    let address = secured_server((&server.0, &server.1), &client.0);
    let port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port().to_string()
    };
    let flags = credential_flags(&client, &server.0);
    let target = uri(address, "/clock");
    let child = binary()
        .args([&flags[..], &["-p", &port, "-s", "3", &target]].concat())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let inbound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    inbound
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // CON POST /.well-known/edhoc, with the true-prefixed start of a message_1.
    let mut request = vec![0x40, 0x02, 0x12, 0x34, 0xbb];
    request.extend_from_slice(b".well-known");
    request.extend_from_slice(&[0x05]);
    request.extend_from_slice(b"edhoc");
    request.extend_from_slice(&[0xff, 0xf5, 0x03, 0x02]);
    inbound
        .send_to(&request, format!("127.0.0.1:{port}"))
        .unwrap();
    let mut reply = [0; 64];
    let (length, _) = inbound.recv_from(&mut reply).unwrap();
    assert!(length >= 4);
    assert_eq!(reply[1], 0x84, "expected 4.04, got {:?}", &reply[..length]);
    assert_code(&wait(child), 0);
}

#[test]
fn exposed_private_key_is_refused_before_any_network_activity() {
    let directory = Directory::new("exposed");
    let client = generate(&directory, "client");
    let server = generate(&directory, "server");
    fs::set_permissions(&client.1, fs::Permissions::from_mode(0o644)).unwrap();
    let flags = credential_flags(&client, &server.0);
    let output = run(&[&flags[..], &["coap://127.0.0.1/hello"]].concat());
    assert_code(&output, 2);
    assert!(stderr(&output).contains("other users"));
}

#[test]
fn generate_identity_refuses_to_overwrite_and_accepts_a_kid() {
    let directory = Directory::new("generate");
    let name = directory.file("own");
    let name = name.to_str().unwrap();
    let output = run(&["--generate-identity", name, "--kid", "0a0b"]);
    assert_code(&output, 0);
    let key = fs::read(directory.file("own.key")).unwrap();
    assert_eq!(
        fs::metadata(directory.file("own.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let ccs = fs::read(directory.file("own.ccs")).unwrap();
    assert!(ccs.windows(2).any(|w| w == [0x0a, 0x0b]));
    let output = run(&["--generate-identity", name]);
    assert_code(&output, 2);
    assert_eq!(fs::read(directory.file("own.key")).unwrap(), key);
}
