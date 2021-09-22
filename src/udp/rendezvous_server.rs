use crate::secure_stream::stream::{SecureStream, ReceiveError};
use crate::async_socket::{UdpSocket, BindError};
use thiserror::Error;
use futures::channel;
use futures::FutureExt;
use std::net::SocketAddr;
use crate::udp::messages::{UdpEchoReq, UdpEchoResp};

#[derive(Debug, Error)]
pub enum RendezvousServerError {
    #[error("bind socket: {0}")]
    BindSocket(#[from] BindError),

    #[error("error while receiving message: {0}")]
    Receive(#[from] ReceiveError)
}


#[derive(Debug, Error)]
pub enum StartupError {
    #[error("server closed while waiting for startup")]
    ServerClosed,
}

pub enum StopStatus {
    NotYetStarted,
    AlreadyStopped,
    Stopped,
}

pub struct Communicator {
    stop_channel: Option<channel::oneshot::Sender<()>>,
    server_address: Result<SocketAddr, channel::oneshot::Receiver<SocketAddr>>,
}

impl Communicator {
    /// Call to stop the server.
    /// Signals the server to stop and then blocks until server is stopped.
    pub fn stop_server(&mut self) -> StopStatus {
        if let Some(i) = self.stop_channel.take() {
            if let Ok(_) = i.send(()) {
                StopStatus::Stopped
            } else {
                StopStatus::AlreadyStopped
            }
        } else {
            StopStatus::NotYetStarted
        }
    }

    /// Get the address of the server. This first waits until the server is started
    /// up and listening and then returns the address the server has gotten. Especially
    /// useful when using 0 as port and you want to know what port the server has gotten.
    pub async fn server_address(&mut self) -> Result<SocketAddr, StartupError> {
        let addr = match self.server_address {
            Ok(ref addr) => return Ok(*addr),
            Err(ref mut chan) => {
                chan.await.map_err(|_| StartupError::ServerClosed)?
            }
        };

        self.server_address = Ok(addr);
        // Unwrap is okay here as we just set the value to Ok.
        Ok(*self.server_address.as_ref().unwrap())
    }

    /// Wait until the server is listening
    pub async fn wait_startup(&mut self) -> Result<(), StartupError> {
        let _ = self.server_address().await;
        Ok(())
    }
}

pub struct RendezvousServer {
    address: SocketAddr,

    stop_channel: channel::oneshot::Receiver<()>,
    startup: channel::oneshot::Sender<SocketAddr>,
}

impl RendezvousServer {
    pub fn with_address(address: impl Into<SocketAddr>) -> (Communicator, Self) {
        fn inner(address: SocketAddr) -> (Communicator, RendezvousServer) {
            let (stop_tx, stop_rx) = channel::oneshot::channel();
            let (start_tx, start_rx) = channel::oneshot::channel();

            (
                Communicator {
                    stop_channel: Some(stop_tx),
                    server_address: Err(start_rx), // start as Err (we don't have the address yet)
                },
                RendezvousServer {
                    address,
                    stop_channel: stop_rx,
                    startup: start_tx,
                }
            )
        }

        inner(address.into())
    }

    pub fn new(port: u16) -> (Communicator, Self) {
        Self::with_address(([0, 0, 0, 0], port))
    }

    pub async fn start<S>(mut self) -> Result<(), RendezvousServerError>
        where
            S: UdpSocket<SendExtra=SocketAddr, RecvExtra=SocketAddr>
    {
        let socket = S::bind(self.address).await?;
        let mut stream = SecureStream::wrap(socket);

        // if this errors, who cares. That means someone dropped
        // the communicator so apparently didn't want to know about
        // the status of the server.
        let _ = self.startup.send(stream.address());

        loop {
            let msg = futures::select! {
                _ = &mut self.stop_channel => break,
                msg = stream.recv_extra().fuse() => msg
            };

            let (UdpEchoReq(pk), addr): (UdpEchoReq, SocketAddr) = match msg {
                Ok(i) => i,
                Err(e) => {
                    log::info!("an error occurred: {}", e);
                    continue
                },
            };

            let resp = pk.anonymously_encrypt_bytes(addr.to_string().as_bytes());
            if let Err(e) =  stream.send_extra(
                UdpEchoResp(resp),
                addr
            ).await {
                log::info!("an error occurred: {}", e);
                continue
            }
        }

        self.stop_channel.close();
        Ok(())
    }
}



#[cfg(test)]
mod tests {
    use crate::udp::rendezvous_server::RendezvousServer;
    use crate::async_socket::{Tokio, UdpSocket};
    use crate::udp::rendezvous_client::RendezvousClient;
    use crate::udp::server_manager::RendezvousServerManager;
    use crate::secure_stream::crypto::KeyPair;

    #[tokio::test]
    async fn respond_with_client_address() {
        // env_logger::builder().filter_level(log::LevelFilter::Trace).init();
        let (mut comm, server) = RendezvousServer::new(0);
        let keypair = KeyPair::gen();

        tokio::spawn(async {
            server.start::<Tokio>().await.unwrap();
        });

        let server_addr = comm.server_address().await.unwrap();

        let mut servers = RendezvousServerManager::new();
        servers.add(server_addr);

        let socket = Tokio::bind(([127, 0, 0, 1], 0).into()).await.unwrap();
        let expected_external_addr = socket.address();
        let c = RendezvousClient::new(servers, keypair, socket);

        let result = c.do_rendezvous().await.unwrap();

        assert_eq!(result.external_address, expected_external_addr);

        comm.stop_server();
    }
}