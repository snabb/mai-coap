//! Complete forwarding helpers for transparent application and security wrappers.

/// Forwards the complete `Application` contract to a field inside an implementation.
/// Use `; except [handle]` to implement selected methods explicitly. Excluded names
/// are checked even when their feature is disabled. Other methods follow the library features.
///
/// Unknown exclusions are rejected:
/// ```compile_fail
/// use mai_coap::{codec::Code, endpoint::{Application, Disposition, Request, ResponseWriter}};
/// struct Wrapper(fn(Request<'_>, &mut ResponseWriter<'_, 128>) -> Result<Disposition, Code>);
/// impl Application<128> for Wrapper {
///     mai_coap::delegate_application!(0, 128; except [handlle]);
/// }
/// ```
#[macro_export]
macro_rules! delegate_application {
    ($field:tt, $size:expr) => {
        $crate::delegate_application!($field, $size; except []);
    };
    ($field:tt, $size:expr; except [$($except:ident),* $(,)?]) => {
        $crate::__delegate_validate!(application; $($except)*);
        $crate::__delegate_method!([$($except)*] handle {
            fn handle(
                &mut self,
                request: $crate::endpoint::Request<'_>,
                response: &mut $crate::endpoint::ResponseWriter<'_, { $size }>,
            ) -> Result<$crate::endpoint::Disposition, $crate::codec::Code> {
                <_ as $crate::endpoint::Application<{ $size }>>::handle(
                    &mut self.$field,
                    request,
                    response,
                )
            }
        });
        $crate::__delegate_method!([$($except)*] recognizes {
            fn recognizes(&self, n: $crate::codec::OptionNumber) -> bool {
                <_ as $crate::endpoint::Application<{ $size }>>::recognizes(&self.$field, n)
            }
        });
        $crate::__delegate_method!([$($except)*] poll {
            fn poll(
                &mut self,
                now: $crate::time::Instant,
                cx: &mut core::task::Context<'_>,
            ) {
                <_ as $crate::endpoint::Application<{ $size }>>::poll(
                    &mut self.$field,
                    now,
                    cx,
                );
            }
        });
        $crate::__delegate_method!([$($except)*] deadline {
            fn deadline(&self) -> Option<$crate::time::Instant> {
                <_ as $crate::endpoint::Application<{ $size }>>::deadline(&self.$field)
            }
        });
        $crate::__delegate_method!([$($except)*] uses_context {
            fn uses_context(&self, generation: u64) -> bool {
                <_ as $crate::endpoint::Application<{ $size }>>::uses_context(&self.$field, generation)
            }
        });
        $crate::__delegate_method!([$($except)*] abort_context {
            fn abort_context(&mut self, generation: u64) {
                <_ as $crate::endpoint::Application<{ $size }>>::abort_context(
                    &mut self.$field,
                    generation,
                );
            }
        });
        $crate::__delegate_application_proxy!($field, $size; [$($except)*]);
        $crate::__delegate_application_observe!($field, $size; [$($except)*]);
    };
}
#[doc(hidden)]
#[cfg(feature = "proxy")]
#[macro_export]
macro_rules! __delegate_application_proxy {
    ($field:tt, $size:expr; [$($except:ident)*]) => {
        $crate::__delegate_method!([$($except)*] forward {
            fn forward(
                &mut self,
                request: $crate::endpoint::Request<'_>,
                now: $crate::time::Instant,
                response: &mut $crate::endpoint::ResponseWriter<'_, { $size }>,
            ) -> Option<Result<$crate::endpoint::Disposition, $crate::codec::Code>> {
                <_ as $crate::endpoint::Application<{ $size }>>::forward(
                    &mut self.$field,
                    request,
                    now,
                    response,
                )
            }
        });
    };
}
#[doc(hidden)]
#[cfg(not(feature = "proxy"))]
#[macro_export]
macro_rules! __delegate_application_proxy {
    ($field:tt, $size:expr; [$($except:ident)*]) => {};
}
#[doc(hidden)]
#[cfg(feature = "observe")]
#[macro_export]
macro_rules! __delegate_application_observe {
    ($field:tt, $size:expr; [$($except:ident)*]) => {
        $crate::__delegate_method!([$($except)*] observable {
            fn observable(
                &self,
                request: $crate::codec::MessageView<'_>,
            ) -> Option<$crate::observe::Settings> {
                <_ as $crate::endpoint::Application<{ $size }>>::observable(&self.$field, request)
            }
        });
    };
}
#[doc(hidden)]
#[cfg(not(feature = "observe"))]
#[macro_export]
macro_rules! __delegate_application_observe {
    ($field:tt, $size:expr; [$($except:ident)*]) => {};
}

/// Forwards the complete `Protection` contract to a field inside an implementation.
/// Pass the inner binding type as the second argument. This includes route/peer
/// dispatch, lifecycle methods, counters and context leases. Use
/// `; except [incoming, outgoing]` to override selected methods.
///
/// Only protection methods may be excluded:
/// ```compile_fail
/// use mai_coap::endpoint::{Protection, Unsecured};
/// struct Wrapper<P>(P);
/// impl<P: Protection> Protection for Wrapper<P> {
///     mai_coap::delegate_protection!(0, P::Binding; except [handle]);
/// }
/// ```
#[macro_export]
macro_rules! delegate_protection {
    ($field:tt, $binding:ty) => {
        $crate::delegate_protection!($field, $binding; except []);
    };
    ($field:tt, $binding:ty; except [$($except:ident),* $(,)?]) => {
        $crate::__delegate_validate!(protection; $($except)*);
        type Binding = $binding;
        $crate::__delegate_method!([$($except)*] random {
            fn random(&mut self, bytes: &mut [u8]) {
                $crate::endpoint::Protection::random(&mut self.$field, bytes);
            }
        });
        $crate::__delegate_method!([$($except)*] requires_request_retention {
            fn requires_request_retention(&self, target: $crate::endpoint::Target) -> bool {
                $crate::endpoint::Protection::requires_request_retention(&self.$field, target)
            }
        });
        $crate::__delegate_method!([$($except)*] outgoing {
            fn outgoing<const DATAGRAM_BYTES: usize>(
                &mut self,
                target: $crate::endpoint::Target,
                message: $crate::codec::MessageView<'_>,
                out: &mut [u8],
            ) -> Result<$crate::endpoint::Prepared<Self::Binding>, $crate::Error> {
                $crate::endpoint::Protection::outgoing::<DATAGRAM_BYTES>(&mut self.$field, target, message, out)
            }
        });
        $crate::__delegate_method!([$($except)*] incoming {
            fn incoming<const DATAGRAM_BYTES: usize>(
                &mut self,
                message: $crate::codec::MessageView<'_>,
                metadata: $crate::transport::Metadata,
                out: &mut [u8],
            ) -> Result<
                (
                    usize,
                    $crate::security::SecurityState,
                    Option<Self::Binding>,
                ),
                $crate::Error,
            > {
                $crate::endpoint::Protection::incoming::<DATAGRAM_BYTES>(&mut self.$field, message, metadata, out)
            }
        });
        $crate::__delegate_method!([$($except)*] response {
            fn response<const DATAGRAM_BYTES: usize>(
                &mut self,
                message: $crate::codec::MessageView<'_>,
                binding: &mut Self::Binding,
                out: &mut [u8],
            ) -> Result<usize, $crate::Error> {
                $crate::endpoint::Protection::response::<DATAGRAM_BYTES>(&mut self.$field, message, binding, out)
            }
        });
        $crate::__delegate_method!([$($except)*] received_response {
            fn received_response<const DATAGRAM_BYTES: usize>(
                &mut self,
                message: $crate::codec::MessageView<'_>,
                binding: &mut Self::Binding,
                out: &mut [u8],
            ) -> Result<usize, $crate::Error> {
                $crate::endpoint::Protection::received_response::<DATAGRAM_BYTES>(
                    &mut self.$field,
                    message,
                    binding,
                    out,
                )
            }
        });
        $crate::__delegate_method!([$($except)*] release {
            fn release(&mut self, binding: Self::Binding) {
                $crate::endpoint::Protection::release(&mut self.$field, binding);
            }
        });
        $crate::__delegate_method!([$($except)*] control {
            fn control<const DATAGRAM_BYTES: usize>(
                &mut self,
                request: $crate::endpoint::Request<'_>,
                now: $crate::time::Instant,
                response: &mut $crate::endpoint::ResponseWriter<'_, DATAGRAM_BYTES>,
            ) -> Result<bool, $crate::Error> {
                $crate::endpoint::Protection::control::<DATAGRAM_BYTES>(&mut self.$field, request, now, response)
            }
        });
        $crate::__delegate_method!([$($except)*] handshake_response {
            fn handshake_response<const DATAGRAM_BYTES: usize>(
                &mut self,
                target: $crate::endpoint::Target,
                message: $crate::codec::MessageView<'_>,
                original: $crate::codec::MessageView<'_>,
                now: $crate::time::Instant,
                out: &mut [u8],
            ) -> Result<$crate::endpoint::Prepared<Self::Binding>, $crate::Error> {
                $crate::endpoint::Protection::handshake_response::<DATAGRAM_BYTES>(
                    &mut self.$field,
                    target,
                    message,
                    original,
                    now,
                    out,
                )
            }
        });
        $crate::__delegate_method!([$($except)*] recover {
            fn recover<const DATAGRAM_BYTES: usize>(
                &mut self,
                target: $crate::endpoint::Target,
                original: $crate::codec::MessageView<'_>,
                now: $crate::time::Instant,
                out: &mut [u8],
            ) -> Result<$crate::endpoint::Prepared<Self::Binding>, $crate::Error> {
                $crate::endpoint::Protection::recover::<DATAGRAM_BYTES>(
                    &mut self.$field,
                    target,
                    original,
                    now,
                    out,
                )
            }
        });
        $crate::__delegate_method!([$($except)*] expire {
            fn expire(&mut self, now: $crate::time::Instant) {
                $crate::endpoint::Protection::expire(&mut self.$field, now);
            }
        });
        $crate::__delegate_method!([$($except)*] deadline {
            fn deadline(&self) -> Option<$crate::time::Instant> {
                $crate::endpoint::Protection::deadline(&self.$field)
            }
        });
        $crate::__delegate_method!([$($except)*] generation {
            fn generation(&self, binding: &Self::Binding) -> Option<u64> {
                $crate::endpoint::Protection::generation(&self.$field, binding)
            }
        });
        $crate::__delegate_method!([$($except)*] pin_epoch {
            fn pin_epoch(&mut self, generation: u64) -> Result<(), $crate::Error> {
                $crate::endpoint::Protection::pin_epoch(&mut self.$field, generation)
            }
        });
        $crate::__delegate_method!([$($except)*] unpin_epoch {
            fn unpin_epoch(&mut self, generation: u64) {
                $crate::endpoint::Protection::unpin_epoch(&mut self.$field, generation);
            }
        });
        $crate::__delegate_method!([$($except)*] handshake_runs {
            fn handshake_runs(&self) -> u64 {
                $crate::endpoint::Protection::handshake_runs(&self.$field)
            }
        });
        $crate::__delegate_method!([$($except)*] context_evictions {
            fn context_evictions(&self) -> u64 {
                $crate::endpoint::Protection::context_evictions(&self.$field)
            }
        });
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __delegate_method {
    ([handle $($rest:ident)*] handle {$($item:tt)*}) => {};
    ([recognizes $($rest:ident)*] recognizes {$($item:tt)*}) => {};
    ([poll $($rest:ident)*] poll {$($item:tt)*}) => {};
    ([deadline $($rest:ident)*] deadline {$($item:tt)*}) => {};
    ([uses_context $($rest:ident)*] uses_context {$($item:tt)*}) => {};
    ([abort_context $($rest:ident)*] abort_context {$($item:tt)*}) => {};
    ([forward $($rest:ident)*] forward {$($item:tt)*}) => {};
    ([observable $($rest:ident)*] observable {$($item:tt)*}) => {};
    ([random $($rest:ident)*] random {$($item:tt)*}) => {};
    ([requires_request_retention $($rest:ident)*] requires_request_retention {$($item:tt)*}) => {};
    ([outgoing $($rest:ident)*] outgoing {$($item:tt)*}) => {};
    ([incoming $($rest:ident)*] incoming {$($item:tt)*}) => {};
    ([response $($rest:ident)*] response {$($item:tt)*}) => {};
    ([received_response $($rest:ident)*] received_response {$($item:tt)*}) => {};
    ([release $($rest:ident)*] release {$($item:tt)*}) => {};
    ([control $($rest:ident)*] control {$($item:tt)*}) => {};
    ([handshake_response $($rest:ident)*] handshake_response {$($item:tt)*}) => {};
    ([recover $($rest:ident)*] recover {$($item:tt)*}) => {};
    ([expire $($rest:ident)*] expire {$($item:tt)*}) => {};
    ([generation $($rest:ident)*] generation {$($item:tt)*}) => {};
    ([pin_epoch $($rest:ident)*] pin_epoch {$($item:tt)*}) => {};
    ([unpin_epoch $($rest:ident)*] unpin_epoch {$($item:tt)*}) => {};
    ([handshake_runs $($rest:ident)*] handshake_runs {$($item:tt)*}) => {};
    ([context_evictions $($rest:ident)*] context_evictions {$($item:tt)*}) => {};
    ([$head:ident $($rest:ident)*] $name:ident {$($item:tt)*}) => {
        $crate::__delegate_method!([$($rest)*] $name {$($item)*});
    };
    ([] $name:ident {$($item:tt)*}) => {$($item)*};
}
#[doc(hidden)]
#[macro_export]
macro_rules! __delegate_validate {
    ($kind:ident;) => {};
    (application; handle $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; recognizes $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; poll $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; deadline $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; uses_context $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; abort_context $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; forward $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (application; observable $($rest:ident)*) => { $crate::__delegate_validate!(application; $($rest)*); };
    (protection; random $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; requires_request_retention $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; outgoing $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; incoming $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; response $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; received_response $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; release $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; control $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; handshake_response $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; recover $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; expire $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; deadline $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; generation $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; pin_epoch $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; unpin_epoch $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; handshake_runs $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    (protection; context_evictions $($rest:ident)*) => { $crate::__delegate_validate!(protection; $($rest)*); };
    ($kind:ident; $unknown:ident $($rest:ident)*) => {
        compile_error!(concat!("unknown ", stringify!($kind), " delegation method: ", stringify!($unknown)));
    };
}
