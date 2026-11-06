//! Turns the URI and addressing flags into a next hop and the URI given to the library.
use crate::{args::Args, exit::Failure};
use mai_coap::{endpoint::Target, uri::Uri};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs, UdpSocket};

/// Where one run sends its requests.
#[derive(Debug)]
pub struct Route {
    pub target: Target,
    /// Absolute URI, or a path when Uri-Host and Uri-Port are suppressed.
    pub uri: String,
    pub proxied: bool,
    pub bind: SocketAddr,
}

/// Checks the scheme and removes an RFC 6874 zone, which is local and never sent.
fn split_zone(input: &str) -> Result<(String, Option<&str>), Failure> {
    let Some((scheme, rest)) = input.split_once("://") else {
        return Err(Failure::local(format!(
            "{input:?} has no scheme; use coap://{input}"
        )));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "coap" => {}
        "coaps" => return Err(unsupported(scheme, "DTLS")),
        "coap+tcp" => return Err(unsupported(scheme, "TCP")),
        "coaps+tcp" => return Err(unsupported(scheme, "TLS")),
        "coap+ws" | "coaps+ws" => return Err(unsupported(scheme, "WebSocket")),
        _ => return Err(Failure::local(format!("unknown URI scheme {scheme:?}"))),
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if let Some(start) = authority.find("%25")
        && let Some(end) = authority[start..].find(']')
    {
        let zone = &authority[start + 3..start + end];
        let stripped = format!(
            "{scheme}://{}{}{}",
            &authority[..start],
            &authority[start + end..],
            &rest[authority_end..]
        );
        return Ok((stripped, Some(zone)));
    }
    Ok((input.to_owned(), None))
}

fn unsupported(scheme: &str, transport: &str) -> Failure {
    Failure::local(format!(
        "{scheme}:// is not supported: mai-coap has no {transport} transport"
    ))
}

fn invalid_uri(input: &str) -> Failure {
    Failure::local(format!("invalid URI {input:?}"))
}

fn interface_index(zone: &str) -> Result<u32, Failure> {
    if let Ok(index) = zone.parse() {
        return Ok(index);
    }
    nix::net::if_::if_nametoindex(zone)
        .map_err(|_| Failure::local(format!("unknown network interface {zone:?}")))
}

fn family_allowed(address: &IpAddr, args: &Args) -> bool {
    !(args.ipv4 && address.is_ipv6() || args.ipv6 && address.is_ipv4())
}

/// Picks the first resolved address with a route, without sending anything.
fn resolve(host: &str, port: u16, args: &Args) -> Result<SocketAddr, Failure> {
    let unresolved = |e: &dyn std::fmt::Display| Failure::network(format!("{host}: {e}"));
    let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        let mut decoded = vec![0; host.len()];
        let n = mai_coap::uri::percent_decode(host.as_bytes(), &mut decoded)
            .map_err(|_| Failure::local(format!("invalid host {host:?}")))?;
        let name = std::str::from_utf8(&decoded[..n])
            .map_err(|_| Failure::local(format!("invalid host {host:?}")))?;
        (name, port)
            .to_socket_addrs()
            .map_err(|e| unresolved(&e))?
            .collect()
    };
    let mut allowed = addresses
        .iter()
        .filter(|a| family_allowed(&a.ip(), args))
        .peekable();
    if allowed.peek().is_none() {
        return Err(unresolved(&"no address of the requested family"));
    }
    let mut last = None;
    for address in allowed {
        match route_exists(*address) {
            Ok(()) => return Ok(*address),
            Err(error) => last = Some(error),
        }
    }
    Err(unresolved(
        &last.map_or_else(|| "no address".to_owned(), |e| e.to_string()),
    ))
}

fn route_exists(address: SocketAddr) -> std::io::Result<()> {
    if address.ip().is_multicast() {
        return Ok(());
    }
    UdpSocket::bind(unspecified(address.is_ipv4()))?.connect(address)
}

fn unspecified(ipv4: bool) -> SocketAddr {
    let ip = if ipv4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, 0)
}

fn with_scope(address: SocketAddr, zone: Option<u32>) -> SocketAddr {
    match (address, zone) {
        (SocketAddr::V6(v6), Some(index)) => {
            SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), v6.flowinfo(), index))
        }
        _ => address,
    }
}

/// Resolves the URI and flags. Blocks on name resolution, before the driver starts.
pub fn route(args: &Args) -> Result<Route, Failure> {
    let input = args.uri.as_deref().unwrap_or_default();
    let (uri, zone) = split_zone(input)?;
    let parsed = Uri::parse(&uri).map_err(|_| invalid_uri(input))?;

    let (next_hop, zone) = if let Some(proxy) = &args.proxy {
        let (proxy_uri, proxy_zone) = split_zone(proxy)?;
        let parsed = Uri::parse(&proxy_uri).map_err(|_| invalid_uri(proxy))?;
        (resolve(parsed.host, parsed.port, args)?, proxy_zone)
    } else {
        (resolve(parsed.host, parsed.port, args)?, zone)
    };
    if next_hop.ip().is_multicast() {
        return Err(Failure::local(
            "multicast destinations are not supported yet",
        ));
    }
    let interface = zone.map(interface_index).transpose()?;
    let remote = with_scope(next_hop, interface);

    let mut target = Target::new(remote);
    target.interface = interface;

    let uri = if args.no_authority {
        let path = if parsed.path.is_empty() {
            "/"
        } else {
            parsed.path
        };
        match parsed.query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        }
    } else {
        uri.clone()
    };

    let mut bind = unspecified(remote.is_ipv4());
    if let Some(address) = args.address {
        if address.is_ipv4() != remote.is_ipv4() {
            return Err(Failure::local(format!(
                "-a {address}: address family differs from the destination {remote}"
            )));
        }
        bind.set_ip(address);
    }
    if let Some(port) = args.port {
        bind.set_port(port);
    }
    Ok(Route {
        target,
        uri,
        proxied: args.proxy.is_some(),
        bind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(arguments: &[&str]) -> Args {
        Args::parse_from(std::iter::once("mai-coap").chain(arguments.iter().copied()))
    }
    fn route_of(arguments: &[&str]) -> Result<Route, Failure> {
        route(&args(arguments))
    }

    #[test]
    fn scheme_is_required_and_secure_schemes_are_never_downgraded() {
        let message = |input| split_zone(input).unwrap_err().message;
        assert!(message("host/path").contains("use coap://host/path"));
        assert!(message("coaps://h/x").contains("no DTLS transport"));
        assert!(message("COAPS://h/x").contains("no DTLS transport"));
        assert!(message("coap+tcp://h/x").contains("no TCP transport"));
        assert!(message("coaps+tcp://h/x").contains("no TLS transport"));
        assert!(message("coap+ws://h/x").contains("no WebSocket transport"));
        assert!(message("coaps+ws://h/x").contains("no WebSocket transport"));
        assert!(message("http://h/x").contains("unknown URI scheme"));
        assert!(split_zone("COAP://h/x").is_ok());
    }

    #[test]
    fn zone_is_removed_from_the_uri() {
        let (uri, zone) = split_zone("coap://[fe80::1%25eth0]:5700/a%25b?q").unwrap();
        assert_eq!(uri, "coap://[fe80::1]:5700/a%25b?q");
        assert_eq!(zone, Some("eth0"));
        let (uri, zone) = split_zone("coap://[::1]/a%25b").unwrap();
        assert_eq!(uri, "coap://[::1]/a%25b");
        assert_eq!(zone, None);
    }

    #[test]
    fn numeric_zones_need_no_lookup_and_set_scope_and_interface() {
        let route = route_of(&["coap://[::1%257]/x"]).unwrap();
        assert_eq!(route.target.interface, Some(7));
        let SocketAddr::V6(v6) = route.target.remote else {
            panic!("expected IPv6");
        };
        assert_eq!(v6.scope_id(), 7);
        assert_eq!(route.uri, "coap://[::1]/x");
        assert!(interface_index("no-such-interface-exists").is_err());
    }

    #[test]
    fn literal_destination_and_default_binding() {
        let route = route_of(&["coap://127.0.0.1:5700/x?q=1"]).unwrap();
        assert_eq!(route.target.remote, "127.0.0.1:5700".parse().unwrap());
        assert_eq!(route.bind, "0.0.0.0:0".parse().unwrap());
        assert_eq!(route.uri, "coap://127.0.0.1:5700/x?q=1");
        assert!(!route.proxied);
        let route = route_of(&["coap://[::1]/x"]).unwrap();
        assert_eq!(route.target.remote.port(), 5683);
        assert_eq!(route.bind, "[::]:0".parse().unwrap());
    }

    #[test]
    fn suppressing_authority_sends_only_path_and_query() {
        assert_eq!(
            route_of(&["-U", "coap://127.0.0.1/a/b?q=1"]).unwrap().uri,
            "/a/b?q=1"
        );
        assert_eq!(route_of(&["-U", "coap://127.0.0.1"]).unwrap().uri, "/");
    }

    #[test]
    fn proxy_is_the_next_hop_and_the_uri_keeps_the_origin() {
        let route = route_of(&["-P", "coap://127.0.0.1:5700", "coap://192.0.2.1/x"]).unwrap();
        assert_eq!(route.target.remote, "127.0.0.1:5700".parse().unwrap());
        assert_eq!(route.uri, "coap://192.0.2.1/x");
        assert!(route.proxied);
        assert!(route_of(&["-P", "coaps://p", "coap://192.0.2.1/x"]).is_err());
    }

    #[test]
    fn bind_flags_apply_and_family_must_match() {
        let route = route_of(&["-a", "127.0.0.1", "-p", "5999", "coap://127.0.0.1/x"]).unwrap();
        assert_eq!(route.bind, "127.0.0.1:5999".parse().unwrap());
        assert!(route_of(&["-a", "::1", "coap://127.0.0.1/x"]).is_err());
    }

    #[test]
    fn family_flags_filter_addresses() {
        assert!(route_of(&["-6", "coap://127.0.0.1/x"]).is_err());
        assert!(route_of(&["-4", "coap://[::1]/x"]).is_err());
        assert!(route_of(&["-4", "coap://127.0.0.1/x"]).is_ok());
    }

    #[test]
    fn multicast_is_refused_and_bad_uris_are_local_errors() {
        let error = route_of(&["coap://224.0.1.187/.well-known/core"]).unwrap_err();
        assert!(error.message.contains("multicast"));
        assert_eq!(
            route_of(&["coap://h@x/"]).unwrap_err().code,
            crate::exit::LOCAL
        );
    }
}
