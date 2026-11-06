//! Bounded resource routing, representation sources and upload modes (SRV, BLK, DSC).
pub mod work;
#[cfg(feature = "block")]
use crate::security::SecurityState;
use crate::{
    Error,
    codec::{Code, ContentFormat, MessageView, OptionNumber},
    endpoint::{Application, Disposition, Request, ResponseWriter},
    security::{Policy, path_matches},
    time::Instant,
};

/// Metadata returned with a random-access representation slice.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct BodyChunk {
    /// Bytes written into caller storage.
    pub written: usize,
    /// Complete representation size, if cheaply known.
    pub total: Option<usize>,
    /// Validator for the complete representation used by this read; mutable
    /// sources must supply one and keep it stable while the bytes stay stable.
    pub etag: heapless::Vec<u8, 8>,
    /// Payload format.
    pub format: ContentFormat,
    /// Freshness lifetime, in seconds.
    pub max_age: u32,
}
impl BodyChunk {
    /// Describes a slice with unknown total length, no ETag and Max-Age 60 seconds.
    pub const fn new(written: usize, format: ContentFormat) -> Self {
        Self {
            written,
            total: None,
            etag: heapless::Vec::new(),
            format,
            max_age: 60,
        }
    }
    /// Sets a complete size when cheaply known.
    pub const fn with_total(mut self, total: Option<usize>) -> Self {
        self.total = total;
        self
    }
    /// Copies an optional ETag, rejecting values longer than eight bytes.
    pub fn with_etag(mut self, etag: &[u8]) -> Result<Self, Error> {
        self.etag = heapless::Vec::from_slice(etag).map_err(|_| Error::Capacity)?;
        Ok(self)
    }
    /// Sets freshness in seconds.
    pub const fn with_max_age(mut self, max_age: u32) -> Self {
        self.max_age = max_age;
        self
    }
}
/// Random-access body generation without retaining a whole representation.
pub trait BodySource {
    /// Writes the representation range beginning at `offset`; metadata describes
    /// the same representation. Return an ETag whenever content can change and
    /// keep it stable across reads while the representation bytes stay stable.
    fn read_at(
        &mut self,
        request: Request<'_>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<BodyChunk, Code>;
}
/// Binary output sink that retains the requested range while hashing the
/// complete rendered representation. Each pass must write one complete, coherent
/// snapshot, including bytes outside the window, to keep the ETag stable across
/// block reads of an unchanged representation.
#[cfg(feature = "block")]
pub struct BodyWindow<'a> {
    offset: usize,
    output: &'a mut [u8],
    total: usize,
    hash: sha2::Sha256,
}

#[cfg(feature = "block")]
impl<'a> BodyWindow<'a> {
    /// Starts collecting the range beginning at `offset`.
    pub fn new(offset: usize, output: &'a mut [u8]) -> Self {
        use sha2::Digest;

        Self {
            offset,
            output,
            total: 0,
            hash: sha2::Sha256::new(),
        }
    }

    /// Appends representation bytes while copying only their overlap with the
    /// requested output range.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Code> {
        use sha2::Digest;

        let end = self
            .total
            .checked_add(bytes.len())
            .ok_or(Code::INTERNAL_ERROR)?;
        let window_end = self.offset.saturating_add(self.output.len());
        let start = self.total.max(self.offset);
        let stop = end.min(window_end);
        if start < stop {
            let source_start = start - self.total;
            let target_start = start - self.offset;
            let count = stop - start;
            self.output[target_start..target_start + count]
                .copy_from_slice(&bytes[source_start..source_start + count]);
        }
        self.hash.update(bytes);
        self.total = end;
        Ok(())
    }

    /// Finishes with total size and a validator for the complete body.
    pub fn finish(self, format: ContentFormat, max_age: u32) -> Result<BodyChunk, Code> {
        use sha2::Digest;

        if self.offset > self.total || self.offset == self.total && self.offset != 0 {
            return Err(Code::BAD_OPTION);
        }
        let written = (self.total - self.offset).min(self.output.len());
        let digest = self.hash.finalize();
        let etag = heapless::Vec::from_slice(&digest[..8]).map_err(|_| Code::INTERNAL_ERROR)?;
        Ok(BodyChunk {
            written,
            total: Some(self.total),
            etag,
            format,
            max_age,
        })
    }
}
/// Read-only static body, useful even when larger than the datagram capacity.
#[derive(Debug)]
#[non_exhaustive]
pub struct SliceBody<'a> {
    /// Complete representation.
    pub bytes: &'a [u8],
    /// Payload format.
    pub format: ContentFormat,
    /// Optional application-computed ETag.
    pub etag: &'a [u8],
    /// Freshness lifetime in seconds.
    pub max_age: u32,
}
impl<'a> SliceBody<'a> {
    /// Uses no ETag and Max-Age 60 seconds.
    pub const fn new(bytes: &'a [u8], format: ContentFormat) -> Self {
        Self {
            bytes,
            format,
            etag: &[],
            max_age: 60,
        }
    }
    /// Borrows an optional ETag, rejecting values longer than eight bytes.
    pub fn with_etag(mut self, etag: &'a [u8]) -> Result<Self, Error> {
        if etag.len() > 8 {
            return Err(Error::Capacity);
        }
        self.etag = etag;
        Ok(self)
    }
    /// Sets freshness in seconds.
    pub const fn with_max_age(mut self, max_age: u32) -> Self {
        self.max_age = max_age;
        self
    }
}
impl BodySource for SliceBody<'_> {
    fn read_at(
        &mut self,
        _: Request<'_>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<BodyChunk, Code> {
        let tail = self.bytes.get(offset..).ok_or(Code::BAD_OPTION)?;
        let n = tail.len().min(output.len());
        output[..n].copy_from_slice(&tail[..n]);
        Ok(BodyChunk {
            written: n,
            total: Some(self.bytes.len()),
            etag: heapless::Vec::from_slice(self.etag).map_err(|_| Code::INTERNAL_ERROR)?,
            format: self.format,
            max_age: self.max_age,
        })
    }
}
enum Target<'a, const DATAGRAM_BYTES: usize> {
    Handler(&'a mut dyn Application<DATAGRAM_BYTES>),
    Representation(&'a mut dyn BodySource),
    #[cfg(feature = "block1")]
    Buffered(&'a mut dyn Application<DATAGRAM_BYTES>),
    #[cfg(feature = "block1")]
    Streaming(&'a mut dyn crate::block::UploadSink, usize),
}
impl<'a, const DATAGRAM_BYTES: usize> Target<'a, DATAGRAM_BYTES> {
    fn application(&self) -> Option<&(dyn Application<DATAGRAM_BYTES> + 'a)> {
        match self {
            Self::Handler(handler) => Some(&**handler),
            #[cfg(feature = "block1")]
            Self::Buffered(handler) => Some(&**handler),
            _ => None,
        }
    }
    fn application_mut(&mut self) -> Option<&mut (dyn Application<DATAGRAM_BYTES> + 'a)> {
        match self {
            Self::Handler(handler) => Some(&mut **handler),
            #[cfg(feature = "block1")]
            Self::Buffered(handler) => Some(&mut **handler),
            _ => None,
        }
    }
}
struct Route<'a, const DATAGRAM_BYTES: usize> {
    path: &'a str,
    methods: &'a [Code],
    attributes: &'a [(&'a str, Option<&'a str>)],
    hidden: bool,
    #[cfg(feature = "observe")]
    observable: Option<crate::observe::Settings>,
    target: Target<'a, DATAGRAM_BYTES>,
}
#[cfg(feature = "block1")]
#[allow(
    clippy::large_enum_variant,
    reason = "buffered and streaming storage is statically bounded"
)]
enum Upload<const UPLOAD_BYTES: usize> {
    Buffered(crate::block::BufferedUpload<UPLOAD_BYTES>),
    Streaming(crate::block::StreamingUpload<1024>),
}
#[cfg(feature = "block1")]
struct BodyEntry<const DATAGRAM_BYTES: usize, const UPLOAD_BYTES: usize> {
    key: crate::block::BodyKey,
    route: usize,
    state: Upload<UPLOAD_BYTES>,
    // Serialized without a token; a duplicate rebinds its current one.
    reply: Option<crate::Packet<DATAGRAM_BYTES>>,
    // Timeout reconfiguration can change deadline order without new progress.
    progressed: Instant,
    deadline: Instant,
}
#[cfg(feature = "block1")]
impl<const DATAGRAM_BYTES: usize, const UPLOAD_BYTES: usize>
    BodyEntry<DATAGRAM_BYTES, UPLOAD_BYTES>
{
    fn closed(&self) -> bool {
        match &self.state {
            Upload::Buffered(upload) => upload.complete_body().is_some(),
            Upload::Streaming(upload) => upload.closed(),
        }
    }
    fn is_duplicate(&self, block: crate::block::Block, bytes: &[u8]) -> bool {
        match &self.state {
            Upload::Buffered(upload) => upload.is_duplicate(block, bytes),
            Upload::Streaming(upload) => upload.is_duplicate(block, bytes),
        }
    }
    fn reclaimable(&self, remote: core::net::SocketAddr, now: Instant) -> bool {
        let idle_ms = self.deadline.elapsed_since(self.progressed).div_ceil(2);
        self.closed()
            || crate::transport::same_peer(self.key.remote, remote)
            || now.elapsed_since(self.progressed) >= idle_ms
    }
}
/// Router with sixteen resources by default. With `block1`, it supports two
/// concurrent Block1 bodies; buffered capacity is 4096 bytes, while streaming
/// bodies use each resource's explicit limit. Table pressure reclaims completed
/// bodies first and protects another remote's unfinished body until half its
/// upload timeout has passed without progress. Discovery is generated by range.
#[cfg_attr(
    not(feature = "block1"),
    doc = r#"
Block1 registration requires the `block1` feature:

```compile_fail
use mai_coap::{
    codec::Code,
    endpoint::{Disposition, Request, ResponseWriter},
    security::PublicPaths,
    server::Router,
};
fn handler(_: Request<'_>, _: &mut ResponseWriter<'_, 128>) -> Result<Disposition, Code> {
    Ok(Disposition::Complete)
}
let policy = PublicPaths(&[]);
let mut router = Router::<128>::new(&policy);
router.buffered_upload("/upload", &[Code::POST], &mut handler);
```
"#
)]
pub struct Router<
    'a,
    const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM },
    const ROUTES: usize = 16,
    const UPLOADS: usize = 2,
    const UPLOAD_BYTES: usize = 4096,
> {
    policy: &'a dyn Policy,
    routes: heapless::Vec<Route<'a, DATAGRAM_BYTES>, ROUTES>,
    now: Instant,
    maximum_szx: u8,
    maximum_unprotected_szx: u8,
    #[cfg(feature = "block1")]
    uploads: heapless::Vec<BodyEntry<DATAGRAM_BYTES, UPLOAD_BYTES>, UPLOADS>,
    #[cfg(feature = "block1")]
    upload_timeout_ms: u64,
}
/// Default-capacity router; use `Router` directly for an explicit resource budget.
pub type DefaultRouter<'a> = Router<'a>;
impl<
    'a,
    const DATAGRAM_BYTES: usize,
    const ROUTES: usize,
    const UPLOADS: usize,
    const UPLOAD_BYTES: usize,
> Router<'a, DATAGRAM_BYTES, ROUTES, UPLOADS, UPLOAD_BYTES>
{
    /// Uses the same policy supplied to the endpoint for discovery visibility.
    pub const fn new(policy: &'a dyn Policy) -> Self {
        Self {
            policy,
            routes: heapless::Vec::new(),
            now: Instant(0),
            maximum_szx: 6,
            maximum_unprotected_szx: 2,
            #[cfg(feature = "block1")]
            uploads: heapless::Vec::new(),
            #[cfg(feature = "block1")]
            upload_timeout_ms: 247_000,
        }
    }
    /// Runs the endpoint using the same policy as discovery visibility.
    /// The lower-level endpoint driver remains available for explicit policies.
    pub async fn run<
        P: crate::endpoint::Protection,
        T: crate::transport::Transport,
        C: crate::time::Clock,
        const OUTBOUND: usize,
        const DEDUP_ENTRIES: usize,
        const OBSERVERS: usize,
        const CACHED_REPLIES: usize,
        const SEND_QUEUE: usize,
        const COMMANDS: usize,
        const DEFERRED: usize,
        const BODY_CONTEXTS: usize,
        const PACKETS: usize,
    >(
        &mut self,
        endpoint: &mut crate::endpoint::Endpoint<
            '_,
            P,
            DATAGRAM_BYTES,
            OUTBOUND,
            DEDUP_ENTRIES,
            OBSERVERS,
            CACHED_REPLIES,
            SEND_QUEUE,
            COMMANDS,
            DEFERRED,
            BODY_CONTEXTS,
            PACKETS,
        >,
        transport: &mut T,
        clock: &C,
    ) -> Result<(), crate::endpoint::RunError<T::Error>> {
        let policy = self.policy;
        endpoint.run(transport, clock, self, policy).await
    }
    /// Sets Block1 inactivity expiry, initially the default 247-second exchange
    /// lifetime. Applications can use their link's transmission parameters.
    /// Other remotes may reclaim unfinished bodies after half this interval
    /// without progress. The interval is recorded when a block advances the body.
    /// Zero returns `Malformed`; existing deadlines are unchanged.
    #[cfg(feature = "block1")]
    pub fn set_upload_timeout(&mut self, timeout_ms: u64) -> Result<(), Error> {
        if timeout_ms == 0 {
            return Err(Error::Malformed);
        }
        self.upload_timeout_ms = timeout_ms;
        Ok(())
    }
    /// Configures path block caps; unprotected default is 64 bytes (DOS-3).
    /// A deployment that serves only unprotected traffic can use
    /// `set_block_caps(6, 6)` to allow blocks up to 1024 bytes, subject to its
    /// datagram capacity.
    pub fn set_block_caps(
        &mut self,
        maximum_szx: u8,
        maximum_unprotected_szx: u8,
    ) -> Result<(), Error> {
        if maximum_szx > 6 || maximum_unprotected_szx > 6 {
            return Err(Error::Malformed);
        }
        self.maximum_szx = maximum_szx;
        self.maximum_unprotected_szx = maximum_unprotected_szx;
        Ok(())
    }
    /// Registers a handler; an empty method list accepts all methods, including unknown ones.
    /// Paths contain decoded URI-Path segments; discovery percent-encodes them.
    pub fn route(
        &mut self,
        path: &'a str,
        methods: &'a [Code],
        handler: &'a mut dyn Application<DATAGRAM_BYTES>,
    ) -> Result<(), Error> {
        self.add(path, methods, Target::Handler(handler))
    }
    /// Registers a GET/FETCH random-access representation.
    pub fn representation(
        &mut self,
        path: &'a str,
        source: &'a mut dyn BodySource,
    ) -> Result<(), Error> {
        self.add(
            path,
            &[Code::GET, Code::FETCH],
            Target::Representation(source),
        )
    }
    /// Registers buffered Block1; the handler sees only a complete body via `Request::payload`.
    #[cfg(feature = "block1")]
    pub fn buffered_upload(
        &mut self,
        path: &'a str,
        methods: &'a [Code],
        handler: &'a mut dyn Application<DATAGRAM_BYTES>,
    ) -> Result<(), Error> {
        self.add(path, methods, Target::Buffered(handler))
    }
    /// Registers transactional Block1 streaming, committed exactly once on final data.
    #[cfg(feature = "block1")]
    pub fn streaming_upload(
        &mut self,
        path: &'a str,
        methods: &'a [Code],
        limit: usize,
        sink: &'a mut dyn crate::block::UploadSink,
    ) -> Result<(), Error> {
        self.add(path, methods, Target::Streaming(sink, limit))
    }
    fn add(
        &mut self,
        path: &'a str,
        methods: &'a [Code],
        target: Target<'a, DATAGRAM_BYTES>,
    ) -> Result<(), Error> {
        if !path.starts_with('/') || self.routes.iter().any(|r| r.path == path) {
            return Err(Error::Malformed);
        }
        self.routes
            .push(Route {
                path,
                methods,
                attributes: &[],
                hidden: false,
                #[cfg(feature = "observe")]
                observable: None,
                target,
            })
            .map_err(|_| Error::Capacity)
    }
    /// Enables observation on a resource with an application-selected change identity.
    /// Returns `Malformed` if another route already uses that identity.
    #[cfg(feature = "observe")]
    pub fn observable(
        &mut self,
        path: &str,
        settings: crate::observe::Settings,
    ) -> Result<crate::observe::ResourceId, Error> {
        crate::observe::Schedule::new(
            self.now,
            settings.minimum_ms,
            settings.maximum_ms,
            settings.confirmable_ms,
        )?;
        if self.routes.iter().any(|route| {
            route.path != path
                && route
                    .observable
                    .is_some_and(|previous| previous.resource == settings.resource)
        }) {
            return Err(Error::Malformed);
        }
        let route = self
            .routes
            .iter_mut()
            .find(|r| r.path == path)
            .ok_or(Error::Malformed)?;
        route.observable = Some(settings);
        Ok(crate::observe::ResourceId(settings.resource))
    }
    /// Sets discovery attributes and visibility on a registered resource.
    /// Returns `Malformed` for invalid names, control characters in values, or
    /// repeated singleton attributes (`ct`, `rt`, `if`, `sz`).
    pub fn describe(
        &mut self,
        path: &str,
        attributes: &'a [(&'a str, Option<&'a str>)],
        hidden: bool,
    ) -> Result<(), Error> {
        crate::link_format_validation::validate_attributes(attributes)?;
        let route = self
            .routes
            .iter_mut()
            .find(|r| r.path == path)
            .ok_or(Error::Malformed)?;
        route.attributes = attributes;
        route.hidden = hidden;
        Ok(())
    }
    fn poll_routes(&mut self, now: Instant, cx: &mut core::task::Context<'_>) {
        self.now = now;
        for route in &mut self.routes {
            if let Some(application) = route.target.application_mut() {
                application.poll(now, cx);
            }
        }
        #[cfg(feature = "block1")]
        {
            let mut i = 0;
            while i < self.uploads.len() {
                if now >= self.uploads[i].deadline {
                    self.remove_upload(i);
                } else {
                    i += 1;
                }
            }
        }
    }
    #[cfg(feature = "block1")]
    fn remove_upload(&mut self, index: usize) {
        let entry = self.uploads.swap_remove(index);
        if matches!(entry.state, Upload::Streaming(ref upload) if !upload.closed())
            && let Target::Streaming(sink, _) = &mut self.routes[entry.route].target
        {
            sink.abort();
        }
    }
    #[cfg(feature = "block1")]
    fn upload(
        &mut self,
        route: usize,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        use crate::block::{BodyKey, BufferedUpload, Progress, StreamingUpload};
        let option = request
            .message
            .option(OptionNumber::BLOCK1)
            .ok_or(Code::BAD_REQUEST)?;
        let block = request_block(option)?;
        let block_size = block.size().map_err(|_| Code::BAD_OPTION)?;
        if request.payload().len() > block_size
            || block.more && request.payload().len() != block_size
        {
            return Err(Code::INCOMPLETE);
        }
        let size = request
            .message
            .option(OptionNumber::SIZE1)
            .map(|o| o.uint().map_err(|_| Code::BAD_OPTION))
            .transpose()?;
        let key = BodyKey::from_request(
            request.metadata.remote,
            route as u32,
            request.context,
            request.message,
        )
        .map_err(|_| Code::BAD_OPTION)?;
        let maximum = match &self.routes[route].target {
            Target::Streaming(_, limit) => *limit,
            _ => UPLOAD_BYTES,
        };
        // Both too-large refusals advertise this route's limit.
        if block.number == 0
            && (request.payload().len() > maximum
                || size.is_some_and(|size| {
                    size > maximum as u64
                        || request.payload().len() as u64 > size
                        || !block.more && request.payload().len() as u64 != size
                }))
        {
            if let Some(i) = self.uploads.iter().position(|entry| entry.key == key) {
                self.remove_upload(i);
            }
            response.set_code(Code::TOO_LARGE);
            response.uint_option(OptionNumber::SIZE1, maximum as u64)?;
            return Ok(Disposition::Complete);
        }
        let deadline = self.now.after(self.upload_timeout_ms);
        let mut existing = self.uploads.iter().position(|entry| entry.key == key);
        if block.number == 0
            && let Some(i) = existing
            && (self.uploads[i].closed() || !self.uploads[i].is_duplicate(block, request.payload()))
        {
            // Preserve the last accepted block's retry; any other block zero restarts.
            self.remove_upload(i);
            existing = None;
        }
        let index = if let Some(i) = existing {
            i
        } else {
            if block.number != 0 {
                return Err(Code::INCOMPLETE);
            }
            if matches!(self.routes[route].target, Target::Streaming(_, _))
                && let Some(i) = self
                    .uploads
                    .iter()
                    .position(|entry| entry.route == route && !entry.closed())
            {
                // Each route has one transactional sink, regardless of table capacity.
                if !self.uploads[i].reclaimable(key.remote, self.now) {
                    response.set_unavailable()?;
                    return Ok(Disposition::Complete);
                }
                self.remove_upload(i);
            }
            if self.uploads.is_full()
                && let Some(i) = self
                    .uploads
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.reclaimable(key.remote, self.now))
                    .min_by_key(|(_, entry)| (!entry.closed(), entry.progressed))
                    .map(|(i, _)| i)
            {
                self.remove_upload(i);
            }
            if self.uploads.is_full() {
                response.set_unavailable()?;
                return Ok(Disposition::Complete);
            }
            let state = match &mut self.routes[route].target {
                Target::Buffered(_) => Upload::Buffered(BufferedUpload::new(deadline)),
                Target::Streaming(sink, limit) => Upload::Streaming(
                    StreamingUpload::begin(&key, size, *limit, deadline, *sink)
                        .map_err(upload_code)?,
                ),
                _ => return Err(Code::METHOD_NOT_ALLOWED),
            };
            self.uploads
                .push(BodyEntry {
                    key,
                    route,
                    state,
                    reply: None,
                    progressed: self.now,
                    deadline,
                })
                .map_err(|_| Code::UNAVAILABLE)?;
            self.uploads.len() - 1
        };
        let result = match &mut self.uploads[index].state {
            Upload::Buffered(upload) => {
                upload.push(block, request.payload(), size, self.now, deadline)
            }
            Upload::Streaming(upload) => match &mut self.routes[route].target {
                Target::Streaming(sink, _) => {
                    upload.push(block, request.payload(), self.now, deadline, *sink)
                }
                _ => return Err(Code::INTERNAL_ERROR),
            },
        };
        let progress = match result {
            Ok(progress) => progress,
            Err(error) => {
                let code = upload_code(error);
                if code == Code::TOO_LARGE {
                    response.set_code(code);
                    response.uint_option(OptionNumber::SIZE1, maximum as u64)?;
                    self.remove_upload(index);
                    return Ok(Disposition::Complete);
                }
                return Err(code);
            }
        };
        if progress != Progress::Duplicate {
            self.uploads[index].progressed = self.now;
            self.uploads[index].deadline = deadline;
        }
        match progress {
            Progress::Duplicate => {
                if let Some(previous) = &self.uploads[index].reply {
                    response.copy_message(
                        MessageView::parse(previous.as_slice())
                            .map_err(|_| Code::INTERNAL_ERROR)?,
                    )?;
                    return Ok(Disposition::Complete);
                } else {
                    return Err(Code::INCOMPLETE);
                }
            }
            Progress::Continue => response.set_code(Code::CONTINUE),
            Progress::Complete => {
                // A deferred or failed final handler must not replay the previous block's reply.
                self.uploads[index].reply = None;
                response.set_code(Code::CHANGED);
                if let (Upload::Buffered(upload), Target::Buffered(handler)) =
                    (&self.uploads[index].state, &mut self.routes[route].target)
                {
                    let body = upload.complete_body().ok_or(Code::INTERNAL_ERROR)?;
                    if handler.handle(Request { body, ..request }, response)?
                        == Disposition::Deferred
                    {
                        return Ok(Disposition::Deferred);
                    }
                }
            }
        }
        response.set_uint_option(
            OptionNumber::BLOCK1,
            block.encode().map_err(|_| Code::BAD_OPTION)?,
        )?;
        self.uploads[index].reply = Some(response.serialized_content()?);
        Ok(Disposition::Complete)
    }
    #[cfg(feature = "discovery")]
    fn discover(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        let mut queries = request.message.values(OptionNumber::URI_QUERY);
        let query = queries
            .next()
            .map(|query| {
                crate::link_format::Query::new(
                    core::str::from_utf8(query).map_err(|_| Code::BAD_REQUEST)?,
                )
                .map_err(|_| Code::BAD_REQUEST)
            })
            .transpose()?;
        if queries.next().is_some() {
            return Err(Code::BAD_REQUEST);
        }
        let routes = &self.routes;
        let policy = self.policy;
        // Reuse unused arena space for policy probes before rendering the body.
        let allowed = response.with_scratch(|scratch| {
            let mut allowed = heapless::Vec::<bool, ROUTES>::new();
            for route in routes {
                let visible = if route.hidden {
                    false
                } else {
                    let mut builder = crate::codec::MessageBuilder::new(
                        scratch,
                        crate::codec::MessageType::NonConfirmable,
                        Code::GET,
                        0,
                        &[],
                    )
                    .map_err(|_| Code::INTERNAL_ERROR)?;
                    if route.path != "/" {
                        for segment in route
                            .path
                            .strip_prefix('/')
                            .unwrap_or(route.path)
                            .split('/')
                        {
                            builder
                                .option(OptionNumber::URI_PATH, segment.as_bytes())
                                .map_err(|_| Code::INTERNAL_ERROR)?;
                        }
                    }
                    let length = builder.finish(&[]).map_err(|_| Code::INTERNAL_ERROR)?;
                    policy.allow(
                        request.security,
                        MessageView::parse(&scratch[..length]).map_err(|_| Code::INTERNAL_ERROR)?,
                    )
                };
                allowed.push(visible).map_err(|_| Code::INTERNAL_ERROR)?;
            }
            Ok(allowed)
        })?;
        let mut source = Discovery {
            routes: &self.routes,
            query,
            allowed,
        };
        render::<DATAGRAM_BYTES>(
            &mut source,
            request,
            response,
            self.maximum_szx,
            self.maximum_unprotected_szx,
        )
    }
}
#[cfg(feature = "discovery")]
struct Discovery<'r, 'a, 'q, const DATAGRAM_BYTES: usize, const ROUTES: usize> {
    routes: &'r [Route<'a, DATAGRAM_BYTES>],
    query: Option<crate::link_format::Query<'q>>,
    allowed: heapless::Vec<bool, ROUTES>,
}
#[cfg(feature = "discovery")]
impl<const DATAGRAM_BYTES: usize, const ROUTES: usize> BodySource
    for Discovery<'_, '_, '_, DATAGRAM_BYTES, ROUTES>
{
    fn read_at(
        &mut self,
        request: Request<'_>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<BodyChunk, Code> {
        let _ = request;
        let mut window = BodyWindow::new(offset, output);
        let mut separator = false;
        for (route, allowed) in self.routes.iter().zip(&self.allowed) {
            if !*allowed
                || self
                    .query
                    .as_ref()
                    .is_some_and(|query| !query.matches_link(route.path, route.attributes))
            {
                continue;
            }
            crate::link_format::write_path_link(route.path, route.attributes, separator, |bytes| {
                window.write(bytes).map_err(|_| Error::Capacity)
            })
            .map_err(|_| Code::INTERNAL_ERROR)?;
            separator = true;
        }
        window.finish(ContentFormat::LINK_FORMAT, 60)
    }
}
impl<
    const DATAGRAM_BYTES: usize,
    const ROUTES: usize,
    const UPLOADS: usize,
    const UPLOAD_BYTES: usize,
> Application<DATAGRAM_BYTES> for Router<'_, DATAGRAM_BYTES, ROUTES, UPLOADS, UPLOAD_BYTES>
{
    fn uses_context(&self, generation: u64) -> bool {
        if self
            .routes
            .iter()
            .filter_map(|r| r.target.application())
            .any(|a| a.uses_context(generation))
        {
            return true;
        }
        #[cfg(feature = "block1")]
        {
            self.uploads.iter().any(|entry| {
                entry.key.context == Some(generation)
                    && match &entry.state {
                        Upload::Buffered(upload) => upload.complete_body().is_none(),
                        Upload::Streaming(upload) => !upload.closed(),
                    }
            })
        }
        #[cfg(not(feature = "block1"))]
        {
            let _ = generation;
            false
        }
    }
    fn abort_context(&mut self, generation: u64) {
        for route in &mut self.routes {
            if let Some(application) = route.target.application_mut() {
                application.abort_context(generation);
            }
        }
        #[cfg(feature = "block1")]
        {
            let mut i = 0;
            while i < self.uploads.len() {
                if self.uploads[i].key.context == Some(generation) {
                    self.remove_upload(i);
                } else {
                    i += 1;
                }
            }
        }
        #[cfg(not(feature = "block1"))]
        let _ = generation;
    }
    #[cfg(feature = "observe")]
    fn observable(&self, request: MessageView<'_>) -> Option<crate::observe::Settings> {
        self.routes
            .iter()
            .find(|r| path_matches(request, r.path))
            .and_then(|r| r.observable)
    }
    fn poll(&mut self, now: Instant, cx: &mut core::task::Context<'_>) {
        self.poll_routes(now, cx);
    }
    fn deadline(&self) -> Option<Instant> {
        let handlers = self
            .routes
            .iter()
            .filter_map(|r| r.target.application()?.deadline())
            .min();
        #[cfg(feature = "block1")]
        {
            self.uploads
                .iter()
                .map(|upload| upload.deadline)
                .chain(handlers)
                .min()
        }
        #[cfg(not(feature = "block1"))]
        {
            handlers
        }
    }
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        #[cfg(feature = "discovery")]
        if path_matches(request.message, "/.well-known/core") {
            if request.message.code() != Code::GET {
                return Err(Code::METHOD_NOT_ALLOWED);
            }
            return self.discover(request, response);
        }
        let route = self
            .routes
            .iter()
            .position(|r| path_matches(request.message, r.path))
            .ok_or(Code::NOT_FOUND)?;
        if !self.routes[route].methods.is_empty()
            && !self.routes[route].methods.contains(&request.message.code())
        {
            return Err(Code::METHOD_NOT_ALLOWED);
        }
        #[cfg(feature = "block1")]
        if matches!(
            self.routes[route].target,
            Target::Buffered(_) | Target::Streaming(_, _)
        ) && request.message.option(OptionNumber::BLOCK1).is_some()
        {
            return self.upload(route, request, response);
        }
        match &mut self.routes[route].target {
            Target::Handler(handler) => handler.handle(request, response),
            Target::Representation(source) => render::<DATAGRAM_BYTES>(
                *source,
                request,
                response,
                self.maximum_szx,
                self.maximum_unprotected_szx,
            ),
            #[cfg(feature = "block1")]
            Target::Buffered(handler) => handler.handle(request, response),
            #[cfg(feature = "block1")]
            Target::Streaming(_, _) => Err(Code::BAD_REQUEST),
        }
    }
    fn recognizes(&self, number: OptionNumber) -> bool {
        self.routes
            .iter()
            .filter_map(|r| r.target.application())
            .any(|a| a.recognizes(number))
    }
}
#[cfg(feature = "block")]
fn request_block(option: crate::codec::MessageOption<'_>) -> Result<crate::block::Block, Code> {
    if option.value.len() > 3 {
        return Err(Code::BAD_OPTION);
    }
    let value = option.uint().map_err(|_| Code::BAD_OPTION)?;
    if value & 7 == 7 {
        return Err(Code::BAD_REQUEST);
    }
    crate::block::Block::decode(value).map_err(|_| Code::BAD_OPTION)
}
#[cfg(feature = "block1")]
fn upload_code(error: Error) -> Code {
    match error {
        Error::Response(code) => code,
        Error::Timeout => Code::INCOMPLETE,
        Error::Capacity => Code::UNAVAILABLE,
        _ => Code::INTERNAL_ERROR,
    }
}
fn render<const DATAGRAM_BYTES: usize>(
    source: &mut dyn BodySource,
    request: Request<'_>,
    response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    maximum: u8,
    unprotected: u8,
) -> Result<Disposition, Code> {
    #[cfg(not(feature = "block"))]
    let (offset, wanted) = {
        let _ = (maximum, unprotected);
        (0, DATAGRAM_BYTES.saturating_sub(96))
    };
    #[cfg(feature = "block")]
    let (offset, wanted, mut block) = {
        let requested = request
            .message
            .option(OptionNumber::BLOCK2)
            .map(request_block)
            .transpose()?
            .unwrap_or(
                crate::block::Block::new(0, false, maximum).map_err(|_| Code::INTERNAL_ERROR)?,
            );
        let mut cap = if matches!(request.security, SecurityState::Unprotected) {
            maximum.min(unprotected)
        } else {
            maximum
        };
        while cap > 0 && (1usize << (cap + 4)) + 96 > DATAGRAM_BYTES {
            cap -= 1;
        }
        let block = requested.capped(cap).map_err(|_| Code::BAD_OPTION)?;
        (
            block.offset().map_err(|_| Code::BAD_OPTION)?,
            block.size().map_err(|_| Code::BAD_OPTION)?,
            block,
        )
    };
    let metadata = response.fill_payload(wanted, |output| {
        let metadata = source.read_at(request, offset, output)?;
        if metadata.written > wanted
            || metadata
                .total
                .is_some_and(|n| offset > n || offset == n && offset != 0)
        {
            return Err(Code::BAD_OPTION);
        }
        Ok((metadata.written, metadata))
    })?;
    if !accepts(request.message, metadata.format) {
        response.set_payload(&[])?;
        return Err(Code::NOT_ACCEPTABLE);
    }
    match preconditions(request.message, &metadata.etag, true) {
        Some(Code::VALID) => {
            response.set_payload(&[])?;
            response.set_code(Code::VALID);
        }
        Some(code) => {
            response.set_payload(&[])?;
            return Err(code);
        }
        None => {
            response.set_code(Code::CONTENT);
        }
    }
    if !metadata.etag.is_empty() {
        response.option(OptionNumber::ETAG, &metadata.etag)?;
    }
    if response.code() == Code::VALID {
        if metadata.max_age != 60 {
            response.uint_option(OptionNumber::MAX_AGE, metadata.max_age.into())?;
        }
        return Ok(Disposition::Complete);
    }
    response.uint_option(OptionNumber::CONTENT_FORMAT, metadata.format.0.into())?;
    if metadata.max_age != 60 {
        response.uint_option(OptionNumber::MAX_AGE, metadata.max_age.into())?;
    }
    #[cfg(feature = "block")]
    {
        block.more = metadata.total.map_or(metadata.written == wanted, |total| {
            offset + metadata.written < total
        });
        if block.more && metadata.written != wanted {
            return Err(Code::INTERNAL_ERROR);
        }
        if block.more || block.number != 0 || request.message.option(OptionNumber::BLOCK2).is_some()
        {
            response.uint_option(
                OptionNumber::BLOCK2,
                block.encode().map_err(|_| Code::BAD_OPTION)?,
            )?;
        }
        if let Some(total) = metadata.total {
            response.uint_option(OptionNumber::SIZE2, total as u64)?;
        }
    }
    #[cfg(not(feature = "block"))]
    if metadata.total.is_some_and(|n| n > metadata.written) {
        return Err(Code::UNAVAILABLE);
    }
    Ok(Disposition::Complete)
}
/// Checks Accept against a produced format (SRV-5).
pub(crate) fn accepts(request: MessageView<'_>, format: ContentFormat) -> bool {
    request
        .option(OptionNumber::ACCEPT)
        .is_none_or(|o| o.uint() == Ok(format.0.into()))
}
/// Applies If-Match, If-None-Match and GET/FETCH ETag validation (SRV-5).
pub(crate) fn preconditions(request: MessageView<'_>, etag: &[u8], exists: bool) -> Option<Code> {
    let mut matches = request.values(OptionNumber::IF_MATCH).peekable();
    if matches.peek().is_some()
        && !matches.any(|value| exists && (value.is_empty() || value == etag))
    {
        return Some(Code::PRECONDITION_FAILED);
    }
    if request.option(OptionNumber::IF_NONE_MATCH).is_some() && exists {
        return Some(Code::PRECONDITION_FAILED);
    }
    if matches!(request.code(), Code::GET | Code::FETCH)
        && !etag.is_empty()
        && request
            .values(OptionNumber::ETAG)
            .any(|value| value == etag)
    {
        return Some(Code::VALID);
    }
    None
}
