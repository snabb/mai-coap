//! Self-contained transactional upload with deferred, worker-side I/O.
use futures_lite::future::race;
use mai_coap::{
    Error,
    block::BodyKey,
    codec::{Code, ContentFormat},
    endpoint::{DefaultEndpoint, DefaultShared, Unsecured},
    security::PublicPaths,
    server::{
        DefaultRouter,
        work::{
            WorkQueue,
            upload::{AsyncUploadSink, UploadWorker},
        },
    },
    time::StdClock,
    transport::linux::StdTransport,
};

#[derive(Default)]
struct Storage {
    staging: Vec<u8>,
    active: Vec<u8>,
}
impl AsyncUploadSink for Storage {
    async fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
        self.staging.clear();
        Ok(())
    }
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset != self.staging.len() {
            return Err(Error::Malformed);
        }
        self.staging.extend_from_slice(bytes);
        Ok(())
    }
    async fn commit(&mut self) -> Result<(), Error> {
        self.active = core::mem::take(&mut self.staging);
        Ok(())
    }
    fn abort(&mut self) {
        self.staging.clear();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_lite::future::block_on(async {
        let mut socket = StdTransport::bind("127.0.0.1:0".parse().unwrap())?;
        let remote = socket.local_addr()?;
        let clock = StdClock::default();
        let policy = PublicPaths(&[(Code::PUT, "/image")]);
        let queue: WorkQueue = WorkQueue::new();
        let mut deferred = queue.handler(247000)?;
        let mut router = DefaultRouter::new(&policy);
        router.route("/image", &[Code::PUT], &mut deferred)?;
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
        let handle = shared.handle();
        let mut worker = UploadWorker::new(&queue, Storage::default(), 65536, 247000)?;
        let worker = worker.run(handle, &clock);
        let client = async {
            let body = vec![0xa5; 4097];
            let reply = handle
                .client(remote)
                .upload(Code::PUT, "/image", ContentFormat::OCTET_STREAM, &body, 6)
                .await?;
            assert_eq!(reply.message()?.code(), Code::CHANGED);
            println!("committed {} bytes", body.len());
            Ok::<_, Error>(())
        };
        race(
            async {
                router.run(&mut endpoint, &mut socket, &clock).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                race(async { match worker.await {} }, client).await?;
                Ok(())
            },
        )
        .await
    })
}
