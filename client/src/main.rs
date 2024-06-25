pub mod aes;
pub mod utils;
pub mod hmac;
pub mod log;
pub mod challenge;
pub mod identify_db;
pub mod cts_cbc;
pub mod pbkdf2;
pub mod message;
pub mod rsaes_oaep;
pub mod auth;
pub mod send_receive;
pub mod sessions_information;

use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::sync::Arc;

use auth::auth_self;
use log::write_log;
use rsaes_oaep::key_generation;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    write_log("Connecté au serveur".to_owned());

    let rsa_key_challenge = Arc::new(key_generation());
    let rsa_key_encryption = Arc::new(key_generation());
    
    let id = "42";
    
    if auth_self(&mut stream, id.to_string(), &rsa_key_challenge, &rsa_key_encryption) {
        write_log("Auth failed".to_owned());
        return Ok(());
    }

    // Lire un message de l'entrée standard et l'envoyer au serveur
    let mut input = String::new();
    println!("Entrez un message : ");
    io::stdin().read_line(&mut input)?;

    stream.write_all(input.as_bytes())?;

    // Lire la réponse du serveur
    let mut buffer = [0; 512];
    let n = stream.read(&mut buffer)?;
    println!("Réponse du serveur : {}", String::from_utf8_lossy(&buffer[..n]));

    Ok(())
}
