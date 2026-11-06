//! Process exit codes and failures that map onto them.
use mai_coap::Error;

pub const SUCCESS: u8 = 0;
pub const ERROR_RESPONSE: u8 = 1;
pub const LOCAL: u8 = 2;
pub const NETWORK: u8 = 3;
pub const SECURITY: u8 = 4;
pub const INTERRUPTED: u8 = 130;

/// A failure that ends the run, with its exit code and a message for stderr.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}
impl Failure {
    pub fn local(message: impl Into<String>) -> Self {
        Self {
            code: LOCAL,
            message: message.into(),
        }
    }
    pub fn network(message: impl Into<String>) -> Self {
        Self {
            code: NETWORK,
            message: message.into(),
        }
    }
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = match error {
            Error::Response(_) => ERROR_RESPONSE,
            Error::Protection
            | Error::Replay
            | Error::ContextNotFound
            | Error::SequenceExhausted
            | Error::Edhoc
            | Error::UnprotectedResponse(_) => SECURITY,
            Error::Capacity
            | Error::InvalidStorage
            | Error::OptionOrder
            | Error::UnsupportedScheme => LOCAL,
            // Timeouts, resets, sends and anything malformed the peer returned.
            _ => NETWORK,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}
impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::local(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mai_coap::codec::Code;

    #[test]
    fn errors_map_to_documented_exit_codes() {
        let code = |error| Failure::from(error).code;
        assert_eq!(code(Error::Response(Code::NOT_FOUND)), ERROR_RESPONSE);
        assert_eq!(code(Error::Timeout), NETWORK);
        assert_eq!(code(Error::Reset), NETWORK);
        assert_eq!(code(Error::LocalSendFailed), NETWORK);
        assert_eq!(code(Error::Malformed), NETWORK);
        assert_eq!(code(Error::RepresentationChanged), NETWORK);
        assert_eq!(code(Error::Edhoc), SECURITY);
        assert_eq!(code(Error::Protection), SECURITY);
        assert_eq!(
            code(Error::UnprotectedResponse(Code::UNAUTHORIZED)),
            SECURITY
        );
        assert_eq!(code(Error::Capacity), LOCAL);
    }
}
