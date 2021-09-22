use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use rand::{thread_rng, Rng};

/// The [`RendezvousServerManager`] is a registry for
/// rendezvous server locations, which can be given to a
/// rendezvous client so it knows where to connect to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RendezvousServerManager {
    servers: Vec<SocketAddr>
}

impl RendezvousServerManager {
    pub fn new() -> Self {
        Self {
            servers: Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn add(&mut self, addr: SocketAddr) {
        self.servers.push(addr);
    }

    // TODO: maybe make iterator and remove rng
    pub fn remove_random(&mut self) -> Option<SocketAddr> {
        if self.servers.len() == 0 {
            None
        } else {
            let mut rng = thread_rng();
            let index = rng.gen_range(0..self.servers.len());
            Some(self.servers.swap_remove(index))
        }
    }
}
