use std::net::SocketAddr;
use bytes::Bytes;
use bincode;
use serde::{Serialize, Deserialize};
use tokio::time::{self, Duration};
use crate::{crypto::CipherSuit, errors::ErrorType, transport::UdpEndpoint};


#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMsg {
    Hello { circuit_id: u32, pubkey: Vec<u8> },
    HelloRelay { circuit_id: u32, pubkey: Vec<u8>, next_hop: SocketAddr },
    RelayAck { circuit_id: u32, relay_pubkey: Vec<u8> },
}

/**
 * performs handshake with each hop in the path
 * @algorithm:
 * 1. send hello msg to first hop
 * 2. receive ack msg from first hop
 * 3. generate shared secret with first hop
 * 4. send hello relay msg to second hop
 * 5. receive ack msg from second hop
 * 6. generate shared secret with second hop
 * 7. repeat for each hop
 * 8. return shared secrets
 */
pub async fn perform_handshake<CS: CipherSuit>(
    endpoint: &UdpEndpoint,
    path: &[SocketAddr]
)-> Result<Vec<CS::SharedSecret>, ErrorType> {
    let mut keys = Vec::with_capacity(path.len());
    let circuit_id = rand::random::<u32>();
    
    let (my_pubkey, my_privkey) = CS::generate_keypair();
    let hello = HandshakeMsg::Hello { 
        circuit_id,
        pubkey: my_pubkey.as_ref().to_vec() 
    };

    endpoint.send_to(&serialize_msg(&hello), path[0]).await?;

    // ack msg:
    let msg = recv_with_timeout(endpoint).await?;
    let relay_pubkey = match msg {
        HandshakeMsg::RelayAck { circuit_id: id, relay_pubkey } if id == circuit_id => relay_pubkey,
        _ => return Err(ErrorType::Protocol("invalid ack msg".into())),
    };

    let _relay_pubkey = CS::pubkey_from_bytes(&relay_pubkey);

    let shared = CS::key_exchange(&_relay_pubkey.unwrap(), my_privkey); // shared secret
    keys.push(shared);

    // extend circuit:
    for i in 1..path.len() {
        let next_hop = path[i];
        let (ext_pubkey, ext_privkey) = CS::generate_keypair();  
        let extend = HandshakeMsg::HelloRelay {
            circuit_id,
            pubkey: ext_pubkey.as_ref().to_vec(),
            next_hop,
        };

        endpoint.send_to(&serialize_msg(&extend), next_hop).await?;
        let msg = recv_with_timeout(endpoint).await?;
        let received_relay_pubkey = match msg {
            HandshakeMsg::RelayAck { circuit_id: id, relay_pubkey } if id == circuit_id => relay_pubkey,
            _ => return Err(ErrorType::Protocol("invalid ack msg".into())),
        };

        let relay_pubkey_formatted = CS::pubkey_from_bytes(&received_relay_pubkey);
        let shared = CS::key_exchange(&relay_pubkey_formatted.unwrap(), ext_privkey); // shared secret
        keys.push(shared);
    }

    Ok(keys)
}

async fn recv_with_timeout(endpoint: &UdpEndpoint) -> Result<HandshakeMsg, ErrorType> {
    let mut buf = [0u8; 1024];
    let recv_fut = endpoint.recv_from(&mut buf);
    
    match time::timeout(Duration::from_secs(5), recv_fut).await {
        Ok(Ok((len, _))) => deserialize_msg(&buf[..len]),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(ErrorType::Protocol("handshake timeout".into())),
    }
}


fn serialize_msg(msg: &HandshakeMsg) -> Bytes {
    Bytes::from(bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap())
}

fn deserialize_msg(buf: &[u8]) -> Result<HandshakeMsg, ErrorType> {
    bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(msg, _)| msg)
        .map_err(|_| ErrorType::Protocol("deserialize failed".into()))
}
