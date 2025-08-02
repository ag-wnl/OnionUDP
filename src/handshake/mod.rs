use std::net::SocketAddr;
use bytes::Bytes;
use bincode;
use serde::{Serialize, Deserialize};
use crate::{crypto::CipherSuit, errors::ErrorType, transport::UdpEndpoint};


#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMsg {
    Hello {pubkey: Vec<u8>},
    HelloRelay {pubkey: Vec<u8>, next_hop: SocketAddr},
    RelayAck {shared_secret: Vec<u8>},
}

pub async fn perform_handshake<CS: CipherSuit>(
    endpoint: &UdpEndpoint,
    path: &[SocketAddr]
)-> Result<Vec<CS::SharedSecret>, ErrorType> {
    let mut keys = Vec::with_capacity(path.len());
    let (my_pubkey, my_privkey) = CS::generate_keypair();

    let hello = HandshakeMsg::Hello { pubkey: my_pubkey.as_ref().to_vec() };
    endpoint.send_to(&serialize_msg(&hello), path[0]).await?;

    for &hop in path {
        let mut buf = [0u8; 1024];
        let (_len, _from) = endpoint.recv_from(&mut buf).await?;
        let msg = deserialize_msg(&buf[.._len])?;

        match msg {
            HandshakeMsg::RelayAck { shared_secret } => {
                let secret = CS::shared_secret_from_bytes(&shared_secret)
                    .map_err(|e| ErrorType::Protocol(format!("corrupt shared secret: {}", e)))?;
                
                keys.push(secret);
            }
    
            _ => return Err(ErrorType::Protocol("incorrect handshake msg".into())),
        }
    }

    Ok(keys)
}


fn serialize_msg(msg: &HandshakeMsg) -> Bytes {
    Bytes::from(bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap())
}

fn deserialize_msg(buf: &[u8]) -> Result<HandshakeMsg, ErrorType> {
    bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(msg, _)| msg)
        .map_err(|_| ErrorType::Protocol("deserialize failed".into()))
}
