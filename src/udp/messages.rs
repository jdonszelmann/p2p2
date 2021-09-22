use serde::{Deserialize, Serialize};

use crate::secure_stream::crypto::public::PublicEncryptKey;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UdpEchoReq(pub PublicEncryptKey);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UdpEchoResp(pub Vec<u8>);
