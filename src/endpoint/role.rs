//! Request roles do not change the endpoint's configured storage capacities or
//! enable Cargo features. Roles are fixed for the endpoint's entire lifetime.

/// Compile-time permission to initiate and serve requests.
/// Downstream implementations may select either permission independently.
///
/// Disabling initiation still permits server responses, retransmissions and their
/// acknowledgements. Disabling serving rejects incoming CON requests with RST
/// and ignores NON requests; responses to initiated requests retain normal
/// duplicate detection. Commands disabled by the role complete with
/// [`crate::Error::RoleDisabled`].
pub trait Role {
    /// Whether cross-task commands may initiate client requests.
    const INITIATE: bool;
    /// Whether incoming requests may reach the application and security layer.
    const SERVE: bool;
}

/// Default combined client and server endpoint.
pub struct Combined;
impl Role for Combined {
    const INITIATE: bool = true;
    const SERVE: bool = true;
}

/// Serves requests and sends responses without initiating client requests.
pub struct Server;
impl Role for Server {
    const INITIATE: bool = false;
    const SERVE: bool = true;
}

/// Initiates client requests without serving incoming requests.
///
/// Duplicate records remain required; full cached replies may have zero capacity.
pub struct Client;
impl Role for Client {
    const INITIATE: bool = true;
    const SERVE: bool = false;
}
