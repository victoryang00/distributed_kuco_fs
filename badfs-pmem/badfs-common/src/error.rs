#[repr(u32)]
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum Error {
    #[error("file not found")]
    NotFound,
    #[error("not dir")]
    NotDir,
    #[error("some feature not supported")]
    NotSupported,
    #[error("Forward to kernel")]
    ForwardToKernel,
}
