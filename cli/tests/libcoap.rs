//! Black-box interoperability with libcoap's example server (`libcoap3-bin` on Ubuntu).
use std::{
    net::UdpSocket,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start() -> (Peer, String) {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let peer = Peer(
        Command::new("coap-server-notls")
            .args(["-A", "127.0.0.1", "-p", &port.to_string(), "-v", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("install libcoap CLI peers"),
    );
    std::thread::sleep(Duration::from_millis(200));
    (peer, format!("coap://127.0.0.1:{port}"))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mai-coap"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn get_and_block_wise_discovery() {
    let (_peer, base) = start();
    let output = run(&[&format!("{base}/time")]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!output.stdout.is_empty());
    for flags in [&[][..], &["-b", "32"], &["-N", "-b", "64"]] {
        let target = format!("{base}/.well-known/core");
        let output = run(&[flags, &[&target]].concat());
        assert_eq!(output.status.code(), Some(0), "{flags:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("</time>"),
            "{flags:?}: {output:?}"
        );
    }
}

#[test]
fn block_wise_put_then_get_round_trips_and_errors_map_to_exit_1() {
    let (_peer, base) = start();
    let target = format!("{base}/example_data");
    let body = "x".repeat(4000);
    let output = run(&[
        "-m",
        "put",
        "-t",
        "plain",
        "-b",
        "128",
        "--payload",
        &body,
        &target,
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = run(&["-b", "256", &target]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    let output = run(&[&format!("{base}/no-such-resource")]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("4.04"));
}

#[test]
fn observe_receives_notifications_and_deregisters() {
    let (_peer, base) = start();
    let output = run(&["-s", "3", "-w", &format!("{base}/time")]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(text.lines().count() >= 2, "{text:?}");
}
