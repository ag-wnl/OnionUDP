use std::net::SocketAddr;

use bytes::Bytes;
use rand::Rng;

use crate::crypto::CipherSuit;
use crate::errors::ErrorType;
use crate::packet::OnionPacket;
use crate::transport::UdpEndpoint;

pub mod builder;
pub use builder::CircuitBuilder;

pub struct Circuit<CS: CipherSuit> {
    keys: Vec<CS::SharedSecret>,
    path: Vec<SocketAddr>,
    endpoint: UdpEndpoint,
    suite: CS,
}

impl<CS: CipherSuit> Circuit<CS> {
    pub async fn send(&self, data: &[u8]) -> Result<(), ErrorType> {
        let mut packet = OnionPacket::new(Bytes::copy_from_slice(data));
        
        let mut nonce = [0u8; 12]; 
        rand::rng().fill(&mut nonce);
        
        for (i, hop) in self.path.iter().enumerate().rev() {
            let aead = CS::new_aead(self.keys[i].as_ref());
            packet.add_layer::<CS>(*hop, aead, &nonce)?;
        }
        self.endpoint.send_to(&packet.payload, self.path[0]).await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, ErrorType> {
        let (len, _) = self.endpoint.recv_from(buf).await?;
        let mut packet = OnionPacket::new(Bytes::copy_from_slice(&buf[..len]));
        
        let mut nonce = [0u8; 12];
        rand::rng().fill(&mut nonce);

        for key in &self.keys {
            let aead = CS::new_aead(key.as_ref());
            packet.remove_layer::<CS>(aead, &nonce)?;
        }
        buf[..packet.payload.len()].copy_from_slice(&packet.payload);
        Ok(packet.payload.len())
    }

    pub async fn close(&self) -> Result<(), ErrorType> {
        Ok(())
    }
}