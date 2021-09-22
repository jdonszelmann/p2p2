use crate::async_socket::{UdpSocket, BindError, ConnectError};
use std::net::SocketAddr;
use crate::secure_stream::stream::{SendBytes, RecvBytes};
use std::error::Error;
use crate::udp::UDP_MAX_SIZE;

pub struct Tokio {
    sock: tokio::net::UdpSocket
}

#[async_trait::async_trait]
impl SendBytes for Tokio {
    async fn send(&mut self, message: &[u8]) -> Result<usize, Box<dyn Error + Send + Sync>> {
        self.sock.send(message).await.map_err(Into::into)
    }

    type SendExtra = SocketAddr;

    async fn send_extra(&mut self, message: &[u8], extra: Self::SendExtra) -> Result<usize, Box<dyn Error + Send + Sync>> {
        self.sock.send_to(message, extra).await.map_err(Into::into)
    }

    fn max_size() -> Option<usize> where Self: Sized {
        Some(UDP_MAX_SIZE)
    }
}

#[async_trait::async_trait]
impl RecvBytes for Tokio {
    async fn recv(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut b = vec![0; UDP_MAX_SIZE];
        let len = self.sock.recv(&mut b).await?;

        b.resize(len, 0);
        Ok(b)
    }

    type RecvExtra = SocketAddr;

    async fn recv_extra(&mut self) -> Result<(Vec<u8>, Self::RecvExtra), Box<dyn Error + Send + Sync>> {
        let mut b = vec![0; UDP_MAX_SIZE];
        let (len, addr) = self.sock.recv_from(&mut b).await?;

        b.resize(len, 0);
        Ok((b, addr))
    }

    fn max_size() -> Option<usize> where Self: Sized {
        Some(UDP_MAX_SIZE)

    }
}

#[async_trait::async_trait]
impl UdpSocket for Tokio {
    async fn bind(address: SocketAddr) -> Result<Self, BindError> {
        let sock = tokio::net::UdpSocket::bind(address)
            .await?;

        Ok(Tokio {
            sock
        })
    }

    async fn connect(&self, address: SocketAddr) -> Result<(), ConnectError> {
        self.sock.connect(address).await?;
        Ok(())
    }

    fn address(&self) -> SocketAddr {
        self.sock.local_addr().expect("somehow couldn't get local address")
    }
}

