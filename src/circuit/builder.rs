use std::net::SocketAddr;

use crate::circuit::Circuit;
use crate::crypto::CipherSuit;
use crate::errors::ErrorType;
use crate::handshake::perform_handshake;
use crate::transport::UdpEndpoint;
use crate::logging::Logger;

pub struct CircuitBuilder<CS: CipherSuit> {
    path: Vec<SocketAddr>,
    suite: CS,
}

impl<CS: CipherSuit> CircuitBuilder<CS> {
    pub fn new(path: Vec<SocketAddr>) -> Self {
        Self { path, suite: CS::new() } 
    }

    /**
     * if you wanna use a cipher suite of your own choice :D
     */
    pub fn with_cipher(self, suite: CS) -> Self {
        Self { suite, ..self }
    }

    /**
     * lays down the whole routing circuit
     * 
     * 1. do path validation
     * 2. bind to a UDP port
     * 3. perform handshakes with each hop/node to get shared secrets 
     * 
     * @returns circuit which can be used to send and receive messages
     */
    pub async fn build(self) -> Result<Circuit<CS>, ErrorType> {
        if self.path.len() < 2 || self.path.len() > 10 {
            return Err(ErrorType::InvalidHops(self.path.len()));
        }

        let endpoint = UdpEndpoint::bind("0.0.0.0:0".parse().unwrap()).await?;
        Logger::circuit(&format!("About to perform handshake | Path: {:?}", &self.path));
        let keys = perform_handshake::<CS>(&endpoint, &self.path).await?;
        
        Ok(Circuit {
            keys,
            path: self.path,
            endpoint,
            suite: self.suite,
        })
    }
}