use bytes::Bytes;   
pub mod chacha_x25519;


pub trait CipherSuit {
    type PubKey: AsRef<[u8]> + Clone;
    type PrivateKey;
    type SharedSecret: AsRef<[u8]>;
    type Aead;

    fn generate_keypair() -> (Self::PubKey, Self::PrivateKey);
    fn key_exchange(pubkey: &Self::PubKey, privkey: Self::PrivateKey) -> Self::SharedSecret;
    fn new_aead(key: &[u8])-> Self::Aead;
    fn encrypt(aead: Self::Aead, nonce: &[u8], plaintext: &[u8])-> Bytes;
    fn decrypt(aead: Self::Aead, nonce: &[u8], ciphertext: &[u8])-> Option<Bytes>;
}


