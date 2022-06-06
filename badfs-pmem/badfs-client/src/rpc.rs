// #[cfg(test)]
// mod rpc_tests {
//     use super::*;
//     use badfs_common::metadata::metadata::Metadata;
//     use badfs_common::rpc::Blob;
//     use once_cell::sync::OnceCell;
//     use std::time::{Duration, SystemTime};
//     use tarpc::tokio_serde::formats::Bincode;
//     use badfs_common::rpc::BadfsServiceClient;
//     static CLIENT: OnceCell<BadfsServiceClient> = OnceCell::new();
//
//     async fn get_client() -> () {
//         const ADDRESS: &str = "0.0.0.0:3343";
//         let stream = tokio::net::TcpStream::connect(ADDRESS).await.unwrap();
//         let transport = tarpc::serde_transport::Transport::from((stream, Bincode::default()));
//         CLIENT
//             .set(BadfsServiceClient::new(tarpc::client::Config::default(), transport).spawn())
//             .unwrap();
//     }
//
//     fn context() -> tarpc::context::Context {
//         let mut cx = tarpc::context::current();
//         cx.deadline = SystemTime::now() + Duration::from_secs(3600);
//         cx
//     }
//
//     async fn test_create_metadata(path: String, metadata: Metadata) {
//         CLIENT
//             .get()
//             .unwrap()
//             .create_metadata(context(), path, metadata)
//             .await
//             .unwrap()
//     }
//
//     async fn test_read_metadata(path: String) -> Option<Metadata> {
//         CLIENT
//             .get()
//             .unwrap()
//             .read_metadata(context(), path)
//             .await
//             .unwrap()
//     }
//
//     async fn test_update_file_metadata_size(path: String, new_file_size: usize) -> () {
//         CLIENT
//             .get()
//             .unwrap()
//             .update_file_metadata_size(context(), path, new_file_size)
//             .await
//             .unwrap()
//     }
//
//     async fn test_remove_metadata(path: String) -> () {
//         CLIENT
//             .get()
//             .unwrap()
//             .remove_metadata(context(), path)
//             .await
//             .unwrap()
//     }
//
//     async fn test_read_file_block(path: String, offset: usize, length: usize) -> Blob {
//         CLIENT
//             .get()
//             .unwrap()
//             .read_file_block(context(), path, offset, length)
//             .await
//             .unwrap()
//     }
//
//     async fn test_write_file_block(path: String, offset: usize, buf: Blob) -> () {
//         CLIENT
//             .get()
//             .unwrap()
//             .write_file_block(context(), path, offset, buf)
//             .await
//             .unwrap()
//     }
//
//     async fn test_remove_file_block(path: String) -> () {
//         CLIENT
//             .get()
//             .unwrap()
//             .remove_file_block(context(), path)
//             .await
//             .unwrap()
//     }
//
//     async fn init(filename: &str) {
//         get_client().await;
//         test_remove_metadata(filename.to_string()).await;
//     }
//
//     #[tokio::test]
//     async fn test() {
//         let filename: String = "a.txt".into();
//
//         init(&filename).await;
//         let metadata = Metadata {
//             mode: libc::DT_REG as u32,
//             size: 0,
//             time: 0,
//         };
//
//         let size = 200;
//         let blob_size = size / 2;
//
//         let mut vec = Vec::<u8>::with_capacity(blob_size);
//         vec.resize(blob_size, 0);
//         let blob = Blob::new(vec);
//
//         assert_eq!(test_read_metadata(filename.clone()).await.is_none(), true);
//
//         test_create_metadata(filename.clone(), metadata).await;
//         assert_eq!(test_read_metadata(filename.clone()).await.is_none(), false);
//
//         test_update_file_metadata_size(filename.clone(), size).await;
//         assert_eq!(
//             test_read_metadata(filename.clone()).await.unwrap().size,
//             size
//         );
//
//         test_write_file_block(filename.clone(), 0, blob.clone()).await;
//         let read_blob = test_read_file_block(filename.clone(), 0, blob_size).await;
//         assert_eq!(read_blob.compare(&blob), true);
//
//         test_remove_file_block(filename.clone()).await;
//         let read_blob = test_read_file_block(filename.clone(), 0, size).await;
//         debug_assert!(read_blob.is_empty());
//
//         test_remove_metadata(filename.clone()).await;
//         assert_eq!(test_read_metadata(filename.clone()).await.is_none(), true);
//     }
// }
