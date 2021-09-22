use crate::secure_stream::stream::{RecvBytes, SendBytes};
use std::net::SocketAddr;
use thiserror::Error;

#[cfg(feature = "runtime-tokio")]
mod tokio_socket;
#[cfg(feature = "runtime-tokio")]
pub use tokio_socket::Tokio;

#[derive(Debug, Error)]
pub enum BindError {
    #[cfg(feature = "runtime-tokio")]
    #[error("tokio bind error: {0}")]
    Tokio(#[from] tokio::io::Error),
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[cfg(feature = "runtime-tokio")]
    #[error("tokio connect error: {0}")]
    Tokio(#[from] tokio::io::Error),
}

#[async_trait::async_trait]
pub trait UdpSocket: Sized + RecvBytes + SendBytes + Unpin {
    // TODO: should bind also take a SocketAddr(V4)
    async fn bind(address: SocketAddr) -> Result<Self, BindError>;

    async fn connect(&self, address: SocketAddr) -> Result<(), ConnectError>;

    fn address(&self) -> SocketAddr;
}

pub trait TcpSocket: Sized {}
