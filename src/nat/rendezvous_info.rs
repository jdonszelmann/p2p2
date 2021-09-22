use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_;
use std::net::SocketAddr;

/// A rendezvous packet.
///
/// This is supposed to be exchanged out of band between the peers to allow them to hole-punch to
/// each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousInfo {
    /// UDP addresses in order. This is not to be re-ordered because we want to match our ttl
    /// runners with peer's (so our slowest will correspond to their slowest etc.) and also make
    /// sure that we are not mis-matching the our-to-peer socket-mapping. Hence not a
    /// Hash/BTreeSet.
    pub udp: Vec<SocketAddr>,
    /// TCP addresses in order
    // TODO: should this be a vec? this is copied from p2p
    //       https://github.com/ustulation/p2p/blob/c7f99c79bd1ef2ea4bd844acd4057ad55a280b6e/src/hole_punch.rs#L65
    pub tcp: Option<SocketAddr>,
    /// Encrypting Asymmetric PublicKey. Peer will use our public key to encrypt and their secret
    /// key to authenticate the message. We will use our secret key to decrypt and peer public key
    /// to validate authenticity of the message.
    pub enc_pk: [u8; box_::PUBLICKEYBYTES],
}

impl RendezvousInfo {
    fn new(enc_pk: &box_::PublicKey) -> Self {
        RendezvousInfo {
            udp: vec![],
            tcp: None,
            enc_pk: enc_pk.0,
        }
    }
}

impl Default for RendezvousInfo {
    fn default() -> Self {
        RendezvousInfo {
            udp: vec![],
            tcp: None,
            enc_pk: [0; box_::PUBLICKEYBYTES],
        }
    }
}
