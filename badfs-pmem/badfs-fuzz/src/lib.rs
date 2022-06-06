use badfs_client::BadfsClient;
use futures::FutureExt;
use once_cell::sync::Lazy;
use std::future::Future;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum ClientOperations {
    ReadRdma(String, u8, u8, u8),
    WriteRdma(String, Vec<u8>, u8),
}

const SERVER_ADDRESS: &str = "localhost:3344";
const CLIENT_COUNT: usize = 16;
static SERVER: Lazy<bool> = Lazy::new(|| {
    start_server();
    true
});

static CLIENTS: Lazy<Vec<BadfsClient>> = Lazy::new(|| {
    assert!(*SERVER);
    (0..CLIENT_COUNT).map(|_| start_client()).collect()
});

static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

pub fn start_server() {
    std::thread::spawn(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(badfs_server::start_server(SERVER_ADDRESS));
    });
    std::thread::sleep(std::time::Duration::from_millis(10))
}

pub fn start_client() -> BadfsClient {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(BadfsClient::new()).unwrap();
    client
}

pub async fn future_wrap<T>(f: impl Future<Output = T>) {
    f.await;
}

pub fn test_client(ops: &[ClientOperations]) {
    let ops_chunk = ops.chunks(CLIENT_COUNT);
    for chunk in ops_chunk {
        let promises: Vec<_> = chunk
            .iter()
            .zip(CLIENTS.iter())
            .map(|(op, client)| {
                async move {
                    match op {
                        ClientOperations::ReadRdma(path, length_0, length_1, offset) => {
                            let mut buf: Vec<u8> =
                                Vec::with_capacity((length_0 + length_1) as usize);
                            buf.resize((length_0 + length_1) as usize, 0);
                            client.read_at(&path, *offset as _, &mut buf).await;
                        }
                        ClientOperations::WriteRdma(path, data, offset) => {
                            let buf = data.as_slice();
                            let buf = unsafe {
                                let len = buf.len();
                                // this is safe because we do not change buf
                                let buf = buf.as_ptr();
                                let buf = buf as *mut u8;
                                std::slice::from_raw_parts_mut(buf, len)
                            };
                            client.write_at(&path, *offset as _, buf).await;
                        }
                    }
                }
            })
            .collect();
        RUNTIME.block_on(futures::future::join_all(promises.into_iter()));
    }
}
