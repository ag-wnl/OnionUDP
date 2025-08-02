use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorType {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Transport   error: {0}")]
    Transport(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Invalid hop count: {0}")]
    InvalidHops(usize),
}