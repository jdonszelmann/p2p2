use serde::{Serialize, Deserialize};
use std::net::IpAddr;


/// Detected NAT Type
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum NatType {
    /// Endpoint Independent Mapping NAT
    EIM,
    /// Predictable Endpoint dependent Mapping NAT. Contains the detected delta.
    EDM(i32),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected IPs.
    EDMRandomIp(Vec<IpAddr>),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected ports.
    EDMRandomPort(Vec<u16>),
    /// Unknown or could not be determined
    Unknown,
}

impl Default for NatType {
    fn default() -> Self {
        NatType::Unknown
    }
}


/// NAT Details
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NatInfo {
    /// Detected NAT Type for TCP
    pub nat_type_for_tcp: NatType,
    /// Detected NAT Type for UDP
    pub nat_type_for_udp: NatType,
}