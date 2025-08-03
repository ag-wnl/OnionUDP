use std::net::SocketAddr;
use bytes::{BufMut, Bytes, BytesMut};
use crate::crypto::CipherSuit;
use crate::errors::ErrorType;

/**
 * Onion packet wrap :D
 */

pub struct OnionPacket {
    pub header: Bytes,
    pub payload: Bytes,
}

impl OnionPacket {
    pub fn new(payload: Bytes)-> Self {
        Self {
            header: Bytes::new(),
            payload,
        }
    }

    pub fn add_layer<CS: CipherSuit>(
        &mut self,
        next_address: SocketAddr,
        aead: CS::Aead,
        nonce: &[u8]
    )-> Result<(), ErrorType> {
        let mut buf = BytesMut::new();
        buf.put(next_address.to_string().as_bytes());
        buf.put(&*self.payload);

        let encrypted = CS::encrypt(aead, nonce, &buf);
        self.payload = encrypted;

        let next_addr_str = next_address.to_string();
        dbg!("add layer | next addr: {:?}", &next_addr_str);

        self.header = Bytes::copy_from_slice(next_addr_str.as_bytes());
        Ok(())
    }

    pub fn remove_layer<CS: CipherSuit>(
        &mut self,
        aead: CS::Aead,
        nonce: &[u8]
    )-> Result<SocketAddr, ErrorType> {
        let decrypted = CS::decrypt(aead, nonce, &self.payload)
        .ok_or(ErrorType::Crypto("Decryption failed".into()))?;

        let (address_bytes, payload) = decrypted.split_at(21); // ipv4 assumption

        let addr_str = std::str::from_utf8(&address_bytes).map_err(|_| ErrorType::Protocol("Invalid addr".into()))?;
        let next_addr: SocketAddr = addr_str.parse().map_err(|_| ErrorType::Protocol("Parse error".into()))?;

        dbg!("remove layer | next addr: {:?}", &next_addr);
        
        self.payload = Bytes::copy_from_slice(payload);
        Ok(next_addr)
    }
}