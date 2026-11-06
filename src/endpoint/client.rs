//! Block-wise client conveniences over the same bounded endpoint handle.
use super::Client;
#[cfg(any(feature = "block1", feature = "observe"))]
use super::Reply;
#[cfg(feature = "block1")]
use crate::codec::ContentFormat;
use crate::{
    Error,
    block::{Block, Download},
    codec::{Code, MessageBuilder, MessageType, OptionNumber},
};

/// Caller-owned destination for a Block2 body; I/O runs in the caller's task.
#[allow(async_fn_in_trait)]
pub trait DownloadSink {
    /// Starts at an offset, with a size hint when known.
    async fn begin(&mut self, offset: usize, total: Option<u64>) -> Result<(), Error>;
    /// Writes ordered body bytes without blocking the endpoint driver.
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Discards a changing representation before restarting at block zero.
    async fn restart(&mut self) -> Result<(), Error>;
    /// Marks a complete, consistent representation ready for application use.
    async fn finish(&mut self, total: usize) -> Result<(), Error>;
}
struct Buffer<'a>(&'a mut [u8]);
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
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Client<'_, DATAGRAM_BYTES, COMMANDS> {
    /// Reassembles a GET representation into caller storage (BLK-3).
    /// Absolute URIs use the origin authority; `through_proxy` adds Proxy-Scheme.
    pub async fn get_blocks(
        self,
        path: &str,
        preferred_szx: u8,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.download(path, preferred_szx, 0, &mut Buffer(output))
            .await
    }
    /// Streams a representation, optionally resuming from the given block number.
    pub async fn download(
        self,
        path: &str,
        preferred_szx: u8,
        resume_block: u32,
        sink: &mut impl DownloadSink,
    ) -> Result<usize, Error> {
        let initial = Block::new(resume_block, false, preferred_szx)?;
        let mut download = Download::new(initial.offset()?);
        let mut szx = preferred_szx;
        let mut started = false;
        loop {
            let next = download.next_offset();
            let block = Block::new((next / (1usize << (szx + 4))) as u32, false, szx)?;
            let mut bytes = [0u8; DATAGRAM_BYTES];
            let mut b =
                MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[])?;
            let absolute = path.contains("://");
            let proxy = self.proxy;
            if proxy && !absolute {
                return Err(Error::Malformed);
            }
            if absolute {
                crate::uri::Uri::parse(path)?
                    .options_with_scratch(&mut b, &mut [0; DATAGRAM_BYTES])?;
            } else {
                crate::uri::resolved_path_query_options(path, &mut b)?;
            }
            b.uint_option(OptionNumber::BLOCK2, block.encode()?)?;
            if proxy {
                b.option(OptionNumber::PROXY_SCHEME, b"coap")?;
            }
            let n = b.finish(&[])?;
            let reply = self.request_raw(&bytes[..n])?.send()?.await?;
            let response = reply.message()?;
            if !response.code().is_success() {
                return Err(Error::Response(response.code()));
            }
            let tag = response.option(OptionNumber::ETAG).map(|o| o.value);
            let received = response
                .option(OptionNumber::BLOCK2)
                .map(|o| Block::decode(o.uint()?))
                .transpose()?;
            if let Some(received) = received {
                if received.szx > szx {
                    return Err(Error::Malformed);
                }
                szx = received.szx;
                if !download.accept(received, response.payload(), tag)? {
                    sink.restart().await?;
                    started = false;
                    continue;
                }
                if !started {
                    let total = response
                        .option(OptionNumber::SIZE2)
                        .map(|o| o.uint())
                        .transpose()?;
                    sink.begin(next, total).await?;
                    started = true;
                }
                sink.write(next, response.payload()).await?;
                if !received.more {
                    let total = download.next_offset();
                    sink.finish(total).await?;
                    return Ok(total);
                }
            } else {
                if next != 0 {
                    return Err(Error::Malformed);
                }
                sink.begin(0, Some(response.payload().len() as u64)).await?;
                sink.write(0, response.payload()).await?;
                sink.finish(response.payload().len()).await?;
                return Ok(response.payload().len());
            }
        }
    }
    /// Sends a body with Block1, stable Request-Tag and size negotiation (BLK-6–7).
    #[cfg(feature = "block1")]
    pub async fn upload(
        self,
        method: Code,
        path: &str,
        format: ContentFormat,
        body: &[u8],
        preferred_szx: u8,
    ) -> Result<Reply<DATAGRAM_BYTES>, Error> {
        self.upload_tagged(method, path, format, body, preferred_szx)
            .await
            .map(|(reply, _)| reply)
    }
    /// Uploads Block1 and reassembles a Block2 response with the same Request-Tag.
    #[cfg(feature = "block1")]
    #[allow(clippy::too_many_arguments, reason = "caller owns both body buffers")]
    pub async fn upload_blocks(
        self,
        method: Code,
        path: &str,
        format: ContentFormat,
        body: &[u8],
        preferred_szx: u8,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let (first, tag) = self
            .upload_tagged(method, path, format, body, preferred_szx)
            .await?;
        let builder = self
            .request(method, path)?
            .uint_option(OptionNumber::CONTENT_FORMAT, format.0.into())?
            .option(OptionNumber::REQUEST_TAG, &tag)?;
        let mut bytes = [0; DATAGRAM_BYTES];
        let n = builder.encode(&mut bytes)?;
        self.complete_blocks(&bytes[..n], first, output).await
    }
    #[cfg(feature = "block1")]
    async fn upload_tagged(
        &self,
        method: Code,
        path: &str,
        format: ContentFormat,
        body: &[u8],
        preferred_szx: u8,
    ) -> Result<(Reply<DATAGRAM_BYTES>, [u8; 8]), Error> {
        if !method.is_request() {
            return Err(Error::Malformed);
        }
        let tag = self.handle.shared.lock(|state| {
            state.body_sequence = state.body_sequence.checked_add(1).ok_or(Error::Capacity)?;
            Ok::<_, Error>(state.body_sequence.to_be_bytes())
        })?;
        let mut offset = 0usize;
        let mut szx = preferred_szx;
        Block::new(0, false, szx)?;
        loop {
            let size = 1usize << (szx + 4);
            let end = offset.saturating_add(size).min(body.len());
            let block = Block::new((offset / size) as u32, end < body.len(), szx)?;
            let reply = self
                .request(method, path)?
                .uint_option(OptionNumber::CONTENT_FORMAT, format.0.into())?
                .uint_option(OptionNumber::BLOCK1, block.encode()?)?
                .uint_option(OptionNumber::SIZE1, body.len() as u64)?
                .option(OptionNumber::REQUEST_TAG, &tag)?
                .payload(&body[offset..end])?
                .send()?;
            let reply = reply.await?;
            let response = reply.message()?;
            let hint = response
                .option(OptionNumber::BLOCK1)
                .map(|o| Block::decode(o.uint()?))
                .transpose()?;
            if response.code() == Code::TOO_LARGE {
                if let Some(hint) = hint
                    && hint.szx < szx
                    && response
                        .option(OptionNumber::SIZE1)
                        .is_none_or(|o| o.uint().is_ok_and(|n| n >= body.len() as u64))
                {
                    szx = hint.szx;
                    continue;
                }
                return Err(Error::Response(response.code()));
            }
            if !response.code().is_success() {
                return Err(Error::Response(response.code()));
            }
            if block.more && response.code() != Code::CONTINUE {
                return Err(Error::Malformed);
            }
            if let Some(hint) = hint {
                if hint.szx > szx {
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
    #[cfg(any(feature = "block1", feature = "observe"))]
    pub(super) async fn complete_blocks(
        &self,
        request: &[u8],
        mut reply: Reply<DATAGRAM_BYTES>,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut state = Download::new(0).with_restart_limit(0);
        loop {
            let message = reply.message()?;
            if !message.code().is_success() {
                return Err(Error::Response(message.code()));
            }
            let offset = state.next_offset();
            let block = message
                .option(OptionNumber::BLOCK2)
                .map(|o| Block::decode(o.uint()?))
                .transpose()?;
            if let Some(block) = block {
                state.accept(
                    block,
                    message.payload(),
                    message.option(OptionNumber::ETAG).map(|o| o.value),
                )?;
            } else if offset != 0 {
                return Err(Error::Malformed);
            }
            let end = offset
                .checked_add(message.payload().len())
                .ok_or(Error::Capacity)?;
            output
                .get_mut(offset..end)
                .ok_or(Error::Capacity)?
                .copy_from_slice(message.payload());
            let Some(block) = block.filter(|b| b.more) else {
                return Ok(end);
            };
            let next = Block::new((end / block.size()?) as u32, false, block.szx)?;
            let original = crate::codec::MessageView::parse(request)?;
            let mut bytes = [0; DATAGRAM_BYTES];
            let mut b = MessageBuilder::new(
                &mut bytes,
                MessageType::Confirmable,
                original.code(),
                0,
                &[],
            )?;
            let mut inserted = false;
            for option in original.options() {
                if matches!(option.number, OptionNumber::OBSERVE | OptionNumber::BLOCK2) {
                    continue;
                }
                if !inserted && option.number > OptionNumber::BLOCK2 {
                    b.uint_option(OptionNumber::BLOCK2, next.encode()?)?;
                    inserted = true;
                }
                b.option(option.number, option.value)?;
            }
            if !inserted {
                b.uint_option(OptionNumber::BLOCK2, next.encode()?)?;
            }
            let n = b.finish(original.payload())?;
            reply = self.request_raw(&bytes[..n])?.send()?.await?;
        }
    }
}
