use onion_udp::{circuit::{self, CircuitBuilder}, crypto::chacha_x25519::ChaCha20Poly1305Suite, relay::RelayService};

/**
 * currently only for testing stuff
 */

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // imitate client:
    println!("initiating client...");
    let path = vec![
        "127.0.0.1:9001".parse()?,
        "127.0.0.1:9002".parse()?,
        "127.0.0.1:9003".parse()?,
    ];
    let builder: CircuitBuilder<ChaCha20Poly1305Suite> = CircuitBuilder::new(path);
    let circuit: circuit::Circuit<_> = builder.build().await?;
    println!("sending message...");
    circuit.send(b"Hello, world!").await?;
    println!("message sent!");

    // imitate relay:
    println!("initiating relay...");
    let relay: RelayService<ChaCha20Poly1305Suite> = RelayService::new("127.0.0.1:9001".parse()?).await;
    println!("relay running...");
    relay.run().await?;

    Ok(())
}