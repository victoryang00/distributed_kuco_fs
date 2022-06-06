use badfs_common::rpc::BadfsServiceClient;
use ibverbs::{CompletionQueue, Context, ProtectionDomain, QueuePair, QueuePairEndpoint};
use once_cell::sync::Lazy;
use std::pin::Pin;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

pub(crate) const CLIENT_CQ_ENTRIES: i32 = 256;

// if memory error occurs, please increase WR_SIZE
const WR_SIZE: u32 = 1024;
pub static WR_READ_FREE: AtomicU32 = AtomicU32::new(WR_SIZE);
pub static WR_WRITE_FREE: AtomicU32 = AtomicU32::new(WR_SIZE);

pub static CONTEXT: Lazy<ibverbs::Context> = Lazy::new(|| {
    ibverbs::devices()
        .unwrap()
        .iter()
        .next()
        .expect("no rdma device available")
        .open()
        .unwrap()
});

pub static PD: Lazy<ibverbs::ProtectionDomain> = Lazy::new(|| CONTEXT.alloc_pd().unwrap());

pub static CQ: Lazy<ibverbs::CompletionQueue> =
    Lazy::new(|| CONTEXT.create_cq(CLIENT_CQ_ENTRIES, 0).unwrap());

#[ouroboros::self_referencing]
pub struct ClientSideConnection<'connection> {
    cq: &'connection CompletionQueue<'connection>,
    pd: &'connection ProtectionDomain<'connection>,
    #[borrows(cq, pd)]
    #[covariant]
    pub qp: QueuePair<'this>,
}

impl<'connection> ClientSideConnection<'connection> {
    pub async fn new_connection<'ctx>(
        ctx: &'ctx Context,
        pd: &'ctx ProtectionDomain<'connection>,
        cq: &'ctx CompletionQueue<'connection>,
        client: &'ctx BadfsServiceClient,
    ) -> ClientSideConnection<'connection>
    where
        'ctx: 'connection,
    {
        let client = client as *const BadfsServiceClient;
        // this is safe because we move client into closure, then execute the closure before function returns
        let client: &'static BadfsServiceClient = unsafe { client.as_ref().unwrap() };
        ClientSideConnectionAsyncBuilder {
            cq,
            pd,
            qp_builder: |cq, pd| -> Pin<Box<_>> {
                Box::pin(async move {
                    let qp_builder = pd
                        .create_qp(&cq, WR_SIZE, &cq, WR_SIZE, ibverbs::ibv_qp_type::IBV_QPT_RC)
                        .build()
                        .expect("failed to build qp");
                    let endpoint = qp_builder.endpoint();
                    let (_, endpoint) = client
                        .handshake(tarpc::context::current(), endpoint)
                        .await
                        .unwrap();
                    qp_builder.handshake(endpoint).expect("handshake failed")
                })
            },
        }
        .build()
        .await
    }
}

pub fn must_pop_cq(completions: &mut [ibverbs::ibv_wc], work_count: &mut u64, free: &AtomicU32) {
    loop {
        let completed = CQ.poll(completions).expect("ERROR: Could not poll CQ.");
        for work_completed_element in completed.iter() {
            if let Some((status, vendor_err)) = work_completed_element.error() {
                panic!("{},{}", status, vendor_err)
            }
        }
        let len = completed.len();
        if len > 0 {
            *work_count -= len as u64;
            free.fetch_add(completed.len() as u32, Relaxed) + completed.len() as u32;
            break;
        }
    }
}
