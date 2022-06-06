const ADDR: &str = "0.0.0.0:3344";

#[tokio::main]
async fn main() {
    badfs_server::start_server(ADDR).await;
}
