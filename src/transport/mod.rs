use std::net::SocketAddr;
use std::time::Duration;


use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Timeout};

use crate::errors::ErrorType;

pub struct UdpEndpoint {
    socket: UdpSocket,
}

/**
 * UDP methods
 */
impl UdpEndpoint {
    pub async fn bind(address: SocketAddr)-> Result<Self, ErrorType> {
        let socket = UdpSocket::bind(address).await?;
        Ok(Self {socket})    
    }

    async fn with_timeout<T>(
        &self, 
        fut: impl std::future::Future<Output = std::io::Result<T>>, 
        duration: Duration
    )-> Result<T, ErrorType> 
    {
            timeout(duration, fut).await
            .map_err(|_| ErrorType::Transport(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))?
            .map_err(From::from) 
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr)-> Result<usize, ErrorType> {
        Ok(self.socket.send_to(buf, target).await?)
    }

    pub async fn recv_from(&self, buf: &mut[u8])-> Result<(usize, SocketAddr), ErrorType> {
        self.with_timeout(self.socket.recv_from(buf), Duration::from_secs(5)).await
    }
}