use super::CipherSuit;
use bytes::Bytes;
use chacha20poly1305::{aead::{Aead, OsRng}, ChaCha20Poly1305, KeyInit};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/**
 * ChaCha20-Poly1305 based methods
 */
impl CipherSuit for ChaCha20Poly1305Suite {
    type PubKey = PublicKey;
    type PrivateKey = EphemeralSecret;
    type SharedSecret = [u8; 32]; // todo: use SharedSecret from x25519_dalek from better type safety
    type Aead = ChaCha20Poly1305;

    fn new() -> Self {
        ChaCha20Poly1305Suite
    }

    fn generate_keypair() -> (Self::PubKey, Self::PrivateKey) {
        let privkey = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = PublicKey::from(&privkey);

        (pubkey, privkey)
    }

    fn key_exchange(pubkey: &Self::PubKey, privkey: Self::PrivateKey) -> Self::SharedSecret {
        let shared_secret = privkey.diffie_hellman(pubkey);
        shared_secret.to_bytes()
    }
    
    fn new_aead(key: &[u8])-> Self::Aead {
        ChaCha20Poly1305::new_from_slice(key).expect("invalid key length")
    }

    fn encrypt(aead: Self::Aead, nonce: &[u8], plaintext: &[u8])-> Bytes {
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        aead.encrypt(nonce, plaintext).expect("failed to encrypt").into()
    }

    fn decrypt(aead: Self::Aead, nonce: &[u8], ciphertext: &[u8])-> Option<Bytes> {
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        aead.decrypt(nonce, ciphertext).ok().map(From::from)
    }

    // helpers:
    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey, &'static str> {
        if bytes.len() != 32 {
            return Err("invalid public key length");
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(PublicKey::from(key_bytes))
    }

    fn shared_secret_from_bytes(bytes: &[u8]) -> Result<Self::SharedSecret, &'static str> {
        if bytes.len() != 32 {
            return Err("invalid shared secret length");
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(bytes);
        Ok(secret_bytes)
    }
}

pub struct ChaCha20Poly1305Suite;
impl ChaCha20Poly1305Suite {
    pub fn new() -> Self {
        Self
    }
}