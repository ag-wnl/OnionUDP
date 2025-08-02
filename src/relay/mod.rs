use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::crypto::CipherSuit;
use crate::errors::ErrorType;
use crate::packet::OnionPacket;

pub struct RelayService<CS: CipherSuit> {
    socket: UdpSocket,
    circuits: HashMap<SocketAddr, CS::SharedSecret>, 
}

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
            let mut packet = OnionPacket::new(Bytes::copy_from_slice(&buf[..len]));
            if let Some(key) = self.circuits.get(&from) {
                let aead = CS::new_aead(key.as_ref());
                let next = packet.remove_layer::<CS>(aead, &[0u8; 12])?; // todo: nonce
                self.socket.send_to(&packet.payload, next).await?;
            }
        }
    }
}