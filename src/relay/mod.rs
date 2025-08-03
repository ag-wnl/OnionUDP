use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use rand::Rng;
use tokio::net::UdpSocket;

use crate::crypto::CipherSuit;
use crate::errors::ErrorType;
use crate::handshake::{deserialize_msg, HandshakeMsg};
use crate::packet::OnionPacket;
use crate::logging::Logger;

pub struct RelayService<CS: CipherSuit> {
    socket: UdpSocket,
    circuits: HashMap<SocketAddr, CS::SharedSecret>, 
}

/**
 * relay service - receives packets from a client and forwards them to the next hop
 * 
 * for key exchange and extending network:
 * @ref - https://security.stackexchange.com/questions/40914/encryption-key-exchange-for-tor
 */
impl<CS: CipherSuit> RelayService<CS> {
    pub async fn new(addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind(addr).await.expect("Bind failed");
        Self {
            socket,
            circuits: HashMap::new(),
        }
    }

    pub async fn run(&self) -> Result<(), ErrorType> {
        let mut buf = [0u8; 1500];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            Logger::packet(&format!("Received packet from: {:?}", &from));

            // parsing msg:
            match deserialize_msg(&buf[..len]) {
                Ok(msg) => {
                    match msg {
                        HandshakeMsg::Hello { circuit_id, pubkey } => {
                            // todo - handle to send back ack
                        }
                        HandshakeMsg::HelloRelay { circuit_id, pubkey, next_hop } => {
                            // todo - handle next hop extension
                        }
                        HandshakeMsg::RelayAck { circuit_id, relay_pubkey } => {
                            // todo - handle ack from relay from extension nodes, back prop to send back ack to client
                        }
                    }
                }
                Err(e) => {
                    Logger::warning(&format!("Failed to deserialize message: {:?}", e));
                }
            }

            let mut packet = OnionPacket::new(Bytes::copy_from_slice(&buf[..len]));
            if let Some(key) = self.circuits.get(&from) {
                Logger::relay(&format!("Processing packet from circuit: {:?}", &from));
                
                let aead = CS::new_aead(key.as_ref());

                let mut nonce = [0u8; 12];
                rand::rng().fill(&mut nonce);
                let next = packet.remove_layer::<CS>(aead, &nonce)?;
                
                Logger::network(&format!("Forwarding packet to next hop: {:?}", next));
                self.socket.send_to(&packet.payload, next).await?;
            } else {
                Logger::warning(&format!("No circuit found for address: {:?}", &from));
            }
        }
    }
}