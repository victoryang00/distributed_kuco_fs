use ibverbs::{CompletionQueue, Context, ProtectionDomain, QueuePair, QueuePairEndpoint};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicIsize, Ordering};

static CQ_COUNT: AtomicIsize = AtomicIsize::new(0);

pub(crate) static CONTEXT: Lazy<ibverbs::Context> = Lazy::new(|| {
    ibverbs::devices()
        .unwrap()
        .iter()
        .next()
        .expect("no rdma device available")
        .open()
        .unwrap()
});

pub(crate) static PD: Lazy<ibverbs::ProtectionDomain> = Lazy::new(|| CONTEXT.alloc_pd().unwrap());

pub static CQ: Lazy<ibverbs::CompletionQueue> = Lazy::new(|| CONTEXT.create_cq(1, 0).unwrap());

#[ouroboros::self_referencing]
pub struct ServerSideConnection<'connection> {
    cq: &'connection CompletionQueue<'connection>,
    pd: &'connection ProtectionDomain<'connection>,
    #[borrows(cq, pd)]
    #[covariant]
    qp: QueuePair<'this>,
}

impl<'connection> ServerSideConnection<'connection> {
    pub fn new_connection<'ctx>(
        ctx: &'ctx Context,
        pd: &'ctx ProtectionDomain<'connection>,
        cq: &'ctx CompletionQueue<'connection>,
        endpoint: QueuePairEndpoint,
    ) -> (Self, QueuePairEndpoint)
    where
        'ctx: 'connection,
    {
        // server will only handle rdma read and rdma write, so it is unnecessary to have big cq_entries
        let mut local_endpoint: Option<QueuePairEndpoint> = None;
        (
            ServerSideConnectionBuilder {
                cq,
                pd,
                qp_builder: |cq, pd| {
                    let qp_builder = pd
                        .create_qp(&cq, 1, &cq, 1, ibverbs::ibv_qp_type::IBV_QPT_RC)
                        .build()
                        .expect("failed to build qp");
                    local_endpoint = Some(qp_builder.endpoint());
                    qp_builder.handshake(endpoint).expect("handshake failed")
                },
            }
            .build(),
            local_endpoint.unwrap(),
        )
    }
}
