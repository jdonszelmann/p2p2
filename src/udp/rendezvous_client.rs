use crate::udp::server_manager::RendezvousServerManager;
use crate::async_socket::{UdpSocket, BindError};
use crate::secure_stream::stream::{SecureStream, ReceiveError};
use thiserror::Error;
use crate::secure_stream::crypto::KeyPair;
use std::net::SocketAddr;
use crate::nat::nat_type::NatType;
use crate::udp::messages::{UdpEchoReq, UdpEchoResp};

#[derive(Debug, Error)]
pub enum RendezvousError {
    #[error("couldn't rendezvous since all rendezvous servers were unreachable or unavailable")]
    NoMoreRVZServers,

    #[error("successfully made contact with rendezvous server but an error occurred while receiving its response: {0}")]
    ReadError(#[from] ReceiveError),

    #[error("Symmetric NAT with variable IP mapping detected. No logic for Udp external address prediction for these circumstances. {0:?}")]
    SymmetricNatVariableIp(NatType),

    #[error("Symmetric NAT with non-uniformly changing port mapping detected. No logic for Udp external address prediction for these circumstances. {0:?}")]
    SymmetricNatNonUniformPortMap(NatType),
}

pub struct RendezvousClient<S> {
    rsm: RendezvousServerManager,
    stream: SecureStream<S>,
    keys: KeyPair,
}

// TODO: make "holepuncher" or similar
pub struct RendezvousSuccessful<S> {
    pub stream: SecureStream<S>,
    pub keys: KeyPair,
    pub external_address: SocketAddr,
    pub nat_type: NatType,
}

impl<S: UdpSocket> RendezvousClient<S> {
    pub fn new(rsm: RendezvousServerManager, keys: KeyPair, socket: S) -> Self {
        Self {
            rsm,
            stream: SecureStream::wrap(socket),
            keys
        }
    }

    pub async fn default_socket(rsm: RendezvousServerManager, keys: KeyPair) -> Result<Self, BindError> {
        let socket = S::bind(([0, 0, 0, 0], 0).into())
            .await?;
        Ok(Self::new(rsm, keys, socket))
    }


    pub async fn do_rendezvous(mut self) -> Result<RendezvousSuccessful<S>, RendezvousError> {

        let num_servers = self.rsm.len();

        // NOTE: DO NOT convert to set - strict ordering is required to pair with peer
        //       More info in [`RendezvousInfo`] documentation
        let mut externally_observed_external_addresses = Vec::with_capacity(num_servers);

        while let Some(address) = self.rsm.remove_random() {
            if let Err(e) = self.stream.connect(address).await {
                log::error!("failed to connect to {}: {}", address, e);
                continue
            }

            // Send them (a RendezvousServer) our public key
            if let Err(e) = self.stream.send(UdpEchoReq(self.keys.public.clone())).await {
                log::error!("failed to send to {}: {}", address, e);
                continue
            }

            // return on error since we already have had contact with this server.
            // If this errors we want to know instead of retry the next server.
            // TODO: Maybe there are even more reasons why we should abort here
            //       the original impl of p2p did this here too.
            let message: UdpEchoResp = self.stream.recv().await?;

            // the response contains our external ip address (as observed by the rendezvous server).
            // it's encrypted and encoded as utf8 bytes (TODO: is this a smart encoding? How about bincode?)
            // try to decrypt/decode the message here.
            let our_external_address_bytes = match self.keys.secret.anonymously_decrypt_bytes(
                &message.0,
                &self.keys.public
            ) {
                Ok(i) => i,
                Err(e) => {
                    log::error!("failed to decrypt, but ignoring (retrying next rendezvous server): {}", e);
                    continue;
                }
            };

            let our_external_address_string = match String::from_utf8(our_external_address_bytes) {
                Ok(i) => i,
                Err(e) => {
                    log::error!("failed to decode utf8, but ignoring (retrying next rendezvous server): {}", e);
                    continue;
                }
            };

            let our_external_address: SocketAddr = match our_external_address_string.parse() {
                Ok(i) => i,
                Err(e) => {
                    log::error!("failed to parse external address, but ignoring (retrying next rendezvous server): {}", e);
                    continue;
                }
            };

            externally_observed_external_addresses.push(our_external_address)
        }

        if externally_observed_external_addresses.len() == 0 {
            log::info!("no more rendezvous servers to try");
            return Err(RendezvousError::NoMoreRVZServers);
        }

        // unwrap is safe because we just checked the length
        let mut assumed_external_address = externally_observed_external_addresses.pop().unwrap();
        let mut addresses = vec![assumed_external_address];
        let mut port_prediction_offset = 0;

        for addr in externally_observed_external_addresses {
            addresses.push(addr);
            if assumed_external_address.ip() != addr.ip() {
                return Err(RendezvousError::SymmetricNatVariableIp(NatType::EDMRandomIp(
                    addresses.into_iter().map(|i| i.ip()).collect()
                )));
            } else if addresses.len() == 2 {
                port_prediction_offset = i32::from(addr.port()) - i32::from(assumed_external_address.port());
            } else if port_prediction_offset !=
                (i32::from(addr.port()) - i32::from(assumed_external_address.port())) {
                return Err(RendezvousError::SymmetricNatNonUniformPortMap(NatType::EDMRandomPort(
                    addresses.into_iter().map(|i| i.port()).collect()
                )));
            }

            assumed_external_address = addr;
        }

        let mut external_address = assumed_external_address;
        let original_port = external_address.port();

        external_address.set_port((i32::from(original_port) + port_prediction_offset) as u16);
        log::debug!("using {:?} as our external address", external_address);

        let nat_type = if port_prediction_offset == 0 {
            NatType::EIM
        } else {
            NatType::EDM(port_prediction_offset)
        };

        Ok(RendezvousSuccessful {
            stream: self.stream,
            keys: self.keys,
            external_address,
            nat_type
        })
    }
}





