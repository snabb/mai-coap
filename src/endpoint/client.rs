//! Block-wise client exchanges over the same bounded endpoint handle.
use super::{Client, Reply, RequestBuilder};
#[cfg(feature = "block1")]
use crate::codec::ContentFormat;
use crate::{
    Error, Packet,
    block::{Block, Download},
    codec::{Code, MessageBuilder, MessageView, OptionNumber, minimal_uint},
};

/// Caller-owned destination for a Block2 body; I/O runs in the caller's task.
///
/// Only a complete, consistent body reaches [`Self::finish`]. [`Self::restart`] discards
/// what was written, on a changed representation or an error response partway through.
#[allow(async_fn_in_trait)]
pub trait DownloadSink {
    /// Starts at an offset, with a size hint when known.
    async fn begin(&mut self, offset: usize, total: Option<u64>) -> Result<(), Error>;
    /// Writes ordered body bytes without blocking the endpoint driver.
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Discards everything written since [`Self::begin`].
    async fn restart(&mut self) -> Result<(), Error>;
    /// Marks a complete, consistent representation ready for application use.
    async fn finish(&mut self, total: usize) -> Result<(), Error>;
}
pub(super) struct Buffer<'a>(pub(super) &'a mut [u8]);
impl DownloadSink for Buffer<'_> {
    async fn begin(&mut self, _: usize, total: Option<u64>) -> Result<(), Error> {
        if total.is_some_and(|n| n > self.0.len() as u64) {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        self.0
            .get_mut(offset..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        Ok(())
    }
    async fn restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn finish(&mut self, _: usize) -> Result<(), Error> {
        Ok(())
    }
}

/// Outcome of a block-wise exchange.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Transfer<const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM }> {
    /// The last response. A non-success code ended the exchange: its diagnostic payload
    /// is here, and the sink holds no body.
    pub reply: Reply<DATAGRAM_BYTES>,
    /// Offset just past the last body byte delivered, including any resumed prefix.
    pub length: usize,
}
impl<const DATAGRAM_BYTES: usize> Transfer<DATAGRAM_BYTES> {
    /// Turns a non-success response code into [`Error::Response`].
    pub fn into_success(self) -> Result<Self, Error> {
        let code = self.reply.message()?.code();
        if code.is_success() {
            Ok(self)
        } else {
            Err(Error::Response(code))
        }
    }
}

/// Block-wise settings collected by [`RequestBuilder`].
#[derive(Clone, Copy, Default)]
pub(super) struct BlockPlan {
    pub(super) szx: Option<u8>,
    /// Asks for `szx` responses on the first retrieval request (RFC 7959 section 2.4).
    pub(super) negotiate: bool,
    pub(super) resume: u32,
}
#[cfg(feature = "observe")]
impl BlockPlan {
    /// Block2 value for an observation request; resuming doesn't apply to one.
    pub(super) fn observe_option(self) -> Result<Option<u64>, Error> {
        if self.resume != 0 {
            return Err(Error::Malformed);
        }
        match self.szx.filter(|_| self.negotiate) {
            Some(szx) => Block::new(0, false, szx)?.encode().map(Some),
            None => Ok(None),
        }
    }
}

/// Largest SZX whose block leaves room for a typical header and options in `datagram`.
const fn default_szx(datagram: usize) -> u8 {
    let mut szx = 6;
    while szx > 0 && (16usize << szx) + 128 > datagram {
        szx -= 1;
    }
    szx
}

/// Serializes `template` with the block options of one request.
///
/// `managed` is in option-number order. Template values of these options never apply:
/// each request carries its own, and Observe only belongs on the registration.
/// If-None-Match applies only to the `first` request (RFC 7959 section 2.10): the
/// exchange itself creates the resource that later requests would then fail against.
fn block_request<const DATAGRAM_BYTES: usize>(
    template: MessageView<'_>,
    managed: &[(OptionNumber, &[u8])],
    payload: &[u8],
    first: bool,
) -> Result<Packet<DATAGRAM_BYTES>, Error> {
    Packet::encoded(|bytes| {
        let mut b = MessageBuilder::new(bytes, template.message_type(), template.code(), 0, &[])?;
        let mut pending = managed;
        for option in template.options() {
            if matches!(
                option.number,
                OptionNumber::OBSERVE
                    | OptionNumber::BLOCK1
                    | OptionNumber::BLOCK2
                    | OptionNumber::SIZE1
            ) || !first && option.number == OptionNumber::IF_NONE_MATCH
            {
                continue;
            }
            while let [(number, value), rest @ ..] = pending
                && *number <= option.number
            {
                b.option(*number, value)?;
                pending = rest;
            }
            b.option(option.number, option.value)?;
        }
        for (number, value) in pending {
            b.option(*number, value)?;
        }
        b.finish(payload)
    })
}

/// The smaller block size a 4.13 asks for, if `body` could still fit at it (RFC 7959
/// section 2.9.3). Any other 4.13 is the final answer, so retries can't loop.
#[cfg(feature = "block1")]
fn smaller_size<const DATAGRAM_BYTES: usize>(
    reply: &Reply<DATAGRAM_BYTES>,
    szx: u8,
    body: usize,
) -> Result<Option<u8>, Error> {
    let response = reply.message()?;
    if response.code() != Code::TOO_LARGE || body == 0 {
        return Ok(None);
    }
    let hint = response
        .option(OptionNumber::BLOCK1)
        .map(|o| Block::decode(o.uint()?))
        .transpose()?;
    let fits = response
        .option(OptionNumber::SIZE1)
        .is_none_or(|o| o.uint().is_ok_and(|limit| limit >= body as u64));
    Ok(hint.map(|hint| hint.szx).filter(|&hint| hint < szx && fits))
}

/// One request template and its submission settings, reused for every block.
struct Exchange<'c, 'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    client: &'c Client<'a, DATAGRAM_BYTES, COMMANDS>,
    template: &'c [u8],
    token_len: u8,
    wait: bool,
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize>
    Exchange<'_, '_, DATAGRAM_BYTES, COMMANDS>
{
    async fn send(&self, packet: Packet<DATAGRAM_BYTES>) -> Result<Reply<DATAGRAM_BYTES>, Error> {
        self.client
            .handle
            .submit_request(self.client.target, packet, self.token_len, self.wait)?
            .await
    }
    /// Sends the body, and any first Block2 request, returning the first final response
    /// and the Request-Tag of a Block1 phase.
    async fn send_body(
        &self,
        plan: BlockPlan,
        body: &[u8],
    ) -> Result<(Reply<DATAGRAM_BYTES>, Option<[u8; 8]>), Error> {
        let szx = plan.szx.unwrap_or(const { default_szx(DATAGRAM_BYTES) });
        let first = Block::new(plan.resume, false, szx)?;
        let negotiate = plan.negotiate || plan.resume != 0;
        if body.len() > first.size()? {
            if plan.resume != 0 {
                return Err(Error::Malformed);
            }
            #[cfg(feature = "block1")]
            return self
                .send_blocks(body, szx, negotiate.then_some(first))
                .await
                .map(|(reply, tag)| (reply, Some(tag)));
            #[cfg(not(feature = "block1"))]
            return Err(Error::Capacity);
        }
        let value = first.encode()?.to_be_bytes();
        let managed = [(OptionNumber::BLOCK2, minimal_uint(&value))];
        let managed = if negotiate { &managed[..] } else { &[] };
        let packet = block_request(MessageView::parse(self.template)?, managed, body, true)?;
        let reply = self.send(packet).await?;
        #[cfg(feature = "block1")]
        if let Some(smaller) = smaller_size(&reply, szx, body.len())? {
            return self
                .send_blocks(body, smaller, negotiate.then_some(first))
                .await
                .map(|(reply, tag)| (reply, Some(tag)));
        }
        Ok((reply, None))
    }
    /// Sends a body in Block1 requests, honouring a smaller size from the server (BLK-6–7).
    #[cfg(feature = "block1")]
    async fn send_blocks(
        &self,
        body: &[u8],
        mut szx: u8,
        negotiate: Option<Block>,
    ) -> Result<(Reply<DATAGRAM_BYTES>, [u8; 8]), Error> {
        let tag = self.client.handle.shared.lock(|state| {
            state.body_sequence = state.body_sequence.checked_add(1).ok_or(Error::Capacity)?;
            Ok::<_, Error>(state.body_sequence.to_be_bytes())
        })?;
        let template = MessageView::parse(self.template)?;
        let mut offset = 0usize;
        loop {
            let size = 1usize << (szx + 4);
            let end = offset.saturating_add(size).min(body.len());
            let number = u32::try_from(offset / size).map_err(|_| Error::Capacity)?;
            let block = Block::new(number, end < body.len(), szx)?;
            let block1 = block.encode()?.to_be_bytes();
            let size1 = (body.len() as u64).to_be_bytes();
            let block2 = negotiate
                .map(Block::encode)
                .transpose()?
                .map(u64::to_be_bytes);
            let tail = [
                (OptionNumber::BLOCK1, minimal_uint(&block1)),
                (OptionNumber::SIZE1, minimal_uint(&size1)),
                (OptionNumber::REQUEST_TAG, tag.as_slice()),
            ];
            // Early Block2 negotiation belongs on the last request (RFC 7959 figure 11).
            let packet = match block2.as_ref().filter(|_| !block.more) {
                Some(block2) => {
                    let [a, b, c] = tail;
                    block_request(
                        template,
                        &[(OptionNumber::BLOCK2, minimal_uint(block2)), a, b, c],
                        &body[offset..end],
                        number == 0,
                    )?
                }
                None => block_request(template, &tail, &body[offset..end], number == 0)?,
            };
            let reply = self.send(packet).await?;
            // Each 4.13 retry strictly shrinks the size, which bounds these restarts.
            if let Some(smaller) = smaller_size(&reply, szx, body.len())? {
                szx = smaller;
                offset = 0;
                continue;
            }
            let response = reply.message()?;
            let code = response.code();
            if !code.is_success() {
                return Ok((reply, tag));
            }
            // A server may act on each block and answer 2.xx with M unset, and the client
            // still sends the rest (RFC 7959 section 2.3). Only the last answer is final.
            if !block.more && code == Code::CONTINUE {
                return Err(Error::Malformed);
            }
            let hint = response
                .option(OptionNumber::BLOCK1)
                .map(|o| Block::decode(o.uint()?))
                .transpose()?;
            if let Some(hint) = hint {
                if hint.szx > szx || hint.number != number {
                    return Err(Error::Malformed);
                }
                szx = hint.szx;
            }
            offset = end;
            if !block.more {
                return Ok((reply, tag));
            }
        }
    }
    /// Retrieves the remaining blocks of a response (BLK-3, RFC 7959 section 2.4).
    ///
    /// `payload` repeats on each request; `tag` keeps the Block1 phase's Request-Tag
    /// (RFC 9175 section 3.4).
    async fn receive(
        &self,
        mut reply: Reply<DATAGRAM_BYTES>,
        mut state: Download,
        mut limit: Option<u8>,
        payload: &[u8],
        tag: Option<&[u8]>,
        sink: &mut impl DownloadSink,
    ) -> Result<Transfer<DATAGRAM_BYTES>, Error> {
        let template = MessageView::parse(self.template)?;
        let mut started = false;
        let mut format = None;
        loop {
            let message = reply.message()?;
            if !message.code().is_success() {
                if started {
                    sink.restart().await?;
                }
                return Ok(Transfer { reply, length: 0 });
            }
            let offset = state.next_offset();
            let block = message
                .option(OptionNumber::BLOCK2)
                .map(|o| Block::decode(o.uint()?))
                .transpose()?;
            let Some(block) = block else {
                if offset != 0 {
                    return Err(Error::Malformed);
                }
                let length = message.payload().len();
                sink.begin(0, Some(length as u64)).await?;
                sink.write(0, message.payload()).await?;
                sink.finish(length).await?;
                return Ok(Transfer { reply, length });
            };
            if limit.is_some_and(|szx| block.szx > szx) {
                return Err(Error::Malformed);
            }
            limit = Some(block.szx);
            let etag = message.option(OptionNumber::ETAG).map(|o| o.value);
            let accepted = state.accept(block, message.payload(), etag)?;
            // Content-Format describes the whole body (RFC 7959 section 2.3).
            let block_format = message
                .option(OptionNumber::CONTENT_FORMAT)
                .map(|o| o.uint())
                .transpose()?;
            if accepted {
                if *format.get_or_insert(block_format) != block_format {
                    return Err(Error::Malformed);
                }
                if !started {
                    let total = message
                        .option(OptionNumber::SIZE2)
                        .map(|o| o.uint())
                        .transpose()?;
                    sink.begin(offset, total).await?;
                    started = true;
                }
                sink.write(offset, message.payload()).await?;
                if !block.more {
                    let length = state.next_offset();
                    sink.finish(length).await?;
                    return Ok(Transfer { reply, length });
                }
            } else {
                sink.restart().await?;
                started = false;
                format = None;
            }
            let number =
                u32::try_from(state.next_offset() / block.size()?).map_err(|_| Error::Capacity)?;
            let value = Block::new(number, false, block.szx)?
                .encode()?
                .to_be_bytes();
            let block2 = (OptionNumber::BLOCK2, minimal_uint(&value));
            let packet = match tag {
                Some(tag) => block_request(
                    template,
                    &[block2, (OptionNumber::REQUEST_TAG, tag)],
                    payload,
                    false,
                )?,
                None => block_request(template, &[block2], payload, false)?,
            };
            reply = self.send(packet).await?;
        }
    }
}

impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize>
    RequestBuilder<'_, DATAGRAM_BYTES, COMMANDS>
{
    /// Prefers this block size exponent in both directions, also asking the server to use
    /// it on the first retrieval request. Without it, bodies that need splitting use the
    /// largest size suited to `DATAGRAM_BYTES`, and the server chooses its response size.
    pub fn block_size(mut self, szx: u8) -> Result<Self, Error> {
        Block::new(0, false, szx)?;
        self.block.szx = Some(szx);
        self.block.negotiate = true;
        Ok(self)
    }
    /// Starts retrieval at this block number, for resuming a GET or FETCH (BLK-3). The
    /// number counts blocks of the [`Self::block_size`] in effect.
    pub fn resume_block(mut self, number: u32) -> Result<Self, Error> {
        Block::new(number, false, 0)?;
        self.block.resume = number;
        Ok(self)
    }
    /// Sends `body`, replacing any [`Self::payload`], and streams the response into `sink`.
    ///
    /// A body larger than the block size uses Block1 with a Request-Tag and Size1, which
    /// needs the `block1` feature and returns [`Error::Capacity`] without it. A smaller
    /// body goes as a plain request. A block-wise response is reassembled across requests.
    /// GET and FETCH restart a bounded number of times if the representation changes;
    /// other methods report [`Error::RepresentationChanged`].
    ///
    /// A non-success response is returned as `Ok`; see [`Transfer`].
    pub async fn transfer(
        mut self,
        body: &[u8],
        sink: &mut impl DownloadSink,
    ) -> Result<Transfer<DATAGRAM_BYTES>, Error> {
        self.content.set_payload(&[])?;
        let method = self.content.code();
        let retrieval = matches!(method, Code::GET | Code::FETCH);
        if self.block.resume != 0 && !retrieval {
            return Err(Error::Malformed);
        }
        let plan = self.block;
        let (client, token_len, wait) = (self.client, self.token_len, self.wait);
        let template = Packet::<DATAGRAM_BYTES>::encoded(|bytes| self.encode(bytes))?;
        drop(self);
        let exchange = Exchange {
            client: &client,
            template: template.as_slice(),
            token_len,
            wait,
        };
        let (first, tag) = exchange.send_body(plan, body).await?;
        let szx = plan.szx.unwrap_or(const { default_szx(DATAGRAM_BYTES) });
        let offset = Block::new(plan.resume, false, szx)?.offset()?;
        let negotiated = (plan.negotiate || plan.resume != 0).then_some(szx);
        let state = Download::new(offset);
        let state = if retrieval && tag.is_none() {
            state
        } else {
            // Repeating the request isn't safe, and the Block1 phase can't be replayed.
            state.with_restart_limit(0)
        };
        // Only FETCH identifies its response by payload (RFC 8132 section 2); otherwise
        // later requests carry none (RFC 7959 figures 10 and 11).
        let repeated = if method == Code::FETCH && tag.is_none() {
            body
        } else {
            &[]
        };
        exchange
            .receive(
                first,
                state,
                negotiated,
                repeated,
                tag.as_ref().map(<[u8; 8]>::as_slice),
                sink,
            )
            .await
    }
    /// As [`Self::transfer`], reassembling the response into caller storage.
    pub async fn transfer_into(
        self,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<Transfer<DATAGRAM_BYTES>, Error> {
        self.transfer(body, &mut Buffer(output)).await
    }
}

impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Client<'_, DATAGRAM_BYTES, COMMANDS> {
    /// Reassembles a GET representation into caller storage (BLK-3).
    /// A non-success response is [`Error::Response`]; use
    /// [`RequestBuilder::transfer`] to read its diagnostic payload.
    pub async fn get_blocks(
        self,
        uri: &str,
        preferred_szx: u8,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let transfer = self
            .request(Code::GET, uri)?
            .block_size(preferred_szx)?
            .transfer_into(&[], output)
            .await?;
        Ok(transfer.into_success()?.length)
    }
    /// Sends a body, using Block1 when it exceeds the block size (BLK-6–7), and returns
    /// the final response without retrieving any further response blocks.
    /// A non-success response is [`Error::Response`].
    #[cfg(feature = "block1")]
    pub async fn upload(
        self,
        method: Code,
        uri: &str,
        format: ContentFormat,
        body: &[u8],
        preferred_szx: u8,
    ) -> Result<Reply<DATAGRAM_BYTES>, Error> {
        let mut builder = self
            .request(method, uri)?
            .uint_option(OptionNumber::CONTENT_FORMAT, format.0.into())?;
        builder.block.szx = Some(preferred_szx);
        let plan = builder.block;
        let (token_len, wait) = (builder.token_len, builder.wait);
        let template = Packet::<DATAGRAM_BYTES>::encoded(|bytes| builder.encode(bytes))?;
        drop(builder);
        let exchange = Exchange {
            client: &self,
            template: template.as_slice(),
            token_len,
            wait,
        };
        let (reply, _) = exchange.send_body(plan, body).await?;
        let code = reply.message()?.code();
        if code.is_success() {
            Ok(reply)
        } else {
            Err(Error::Response(code))
        }
    }
    /// Completes a notification, using `template` as the follow-up request (OBS-6).
    #[cfg(feature = "observe")]
    pub(super) async fn complete_notification(
        &self,
        template: &[u8],
        first: Reply<DATAGRAM_BYTES>,
        sink: &mut impl DownloadSink,
    ) -> Result<Transfer<DATAGRAM_BYTES>, Error> {
        let view = MessageView::parse(template)?;
        let limit = view
            .option(OptionNumber::BLOCK2)
            .map(|o| Block::decode(o.uint()?))
            .transpose()?
            .map(|block| block.szx);
        let exchange = Exchange {
            client: self,
            template,
            token_len: 8,
            wait: true,
        };
        exchange
            .receive(
                first,
                Download::new(0).with_restart_limit(0),
                limit,
                view.payload(),
                None,
                sink,
            )
            .await
    }
}
