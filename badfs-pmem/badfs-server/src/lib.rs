mod rdma;
mod rpc;

use once_cell::sync::Lazy;
use tarpc::server;
use tarpc::server::Channel;
use tokio_serde::formats::Bincode;

use badfs_common::rpc::BadfsService;

use rpc::*;

pub async fn start_server(server_address: &str) {
    env_logger::init();

    let rpc_handler = BadfsServer::new(&rdma::CONTEXT, &rdma::PD, &rdma::CQ);
    let listener = tokio::net::TcpListener::bind(server_address).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let transport = tarpc::serde_transport::Transport::from((stream, Bincode::default()));
        let server = server::BaseChannel::with_defaults(transport);

        tokio::spawn(server.execute(rpc_handler.clone().serve()));
    }
}
