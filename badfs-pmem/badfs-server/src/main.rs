const ADDR: &str = "0.0.0.0:3345";
use corundum::open_flags::*;
use corundum::*;
type P = corundum::default::Allocator;
#[tokio::main]
async fn main() {
    let _pool = P::open_no_root("/mnt/pmem0p1/test.pool", O_CF | O_1TB).unwrap();
    badfs_server::start_server(ADDR).await;
}
