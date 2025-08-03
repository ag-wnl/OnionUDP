use std::env;
use onion_udp::{circuit::{self, CircuitBuilder}, crypto::chacha_x25519::ChaCha20Poly1305Suite, relay::RelayService, logging::Logger};


/**
 * @setup: 
 * to run relayers:
 * cargo run -- --relay 9001
 * cargo run -- --relay 9002
 * cargo run -- --relay 9003
 * 
 * to run client:
 * cargo run -- --client
 */


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // client or relay from args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        Logger::error(&format!("Usage: {} --client | --relay <port>", args[0]));
        return Ok(());
    }

    match args[1].as_str() {
        "--client" => {
            Logger::client("Initiating client...");
            let path = vec![
                "127.0.0.1:9001".parse()?,
                "127.0.0.1:9002".parse()?,
                "127.0.0.1:9003".parse()?,
            ];

            Logger::circuit(&format!("Path: {:?} | Building circuit...", path));
            let builder: CircuitBuilder<ChaCha20Poly1305Suite> = CircuitBuilder::new(path);
            Logger::success("Circuit builder created successfully");
            let circuit: circuit::Circuit<_> = builder.build().await?;
            
            Logger::info("Sending message through circuit...");
            circuit.send(b"Hello, world!").await?;
            Logger::success("Message sent successfully!");
        }
        "--relay" => {
            if args.len() < 3 {
                Logger::error(&format!("Usage: {} --relay <port>", args[0]));
                return Ok(());
            }
            let port = &args[2];
            let relay_address = format!("127.0.0.1:{}", port);

            Logger::relay(&format!("Starting relay on {}", relay_address));
            let relay: RelayService<ChaCha20Poly1305Suite> = RelayService::new(relay_address.parse()?).await;
            Logger::success(&format!("Relay running on {}", relay_address));
            relay.run().await?;
        }
        _ => {
            Logger::error("Invalid mode. Use --client or --relay <port>");
        }
    }

    Ok(())
}