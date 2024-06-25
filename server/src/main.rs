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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use auth::auth_client;
use identify_db::write_db_id;
use log::write_log;
use rsaes_oaep::{key_generation, RsaKey};

fn handle_client(mut stream: TcpStream, key_challenge: &RsaKey, key_encryption: &RsaKey) {
    let mut buffer = [0; 8192];

    if !auth_client(&mut stream, key_challenge, key_encryption) {
        write_log("Auth failed : next client".to_owned());
        return;
    }

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                write_log("Close connexion".to_owned());
                break;
            }
            Ok(n) => {
                // Écrire les données reçues sur la sortie standard
                write_log(["Received : ", &String::from_utf8_lossy(&buffer[..n])].concat());
                // Envoyer une réponse au client
                if let Err(e) = stream.write_all(b"ACK\n") {
                    write_log(["Erreur lors de l'envoi de la réponse : ", &e.to_string()].concat());
                    break;
                }
            }
            Err(e) => {
                write_log(["Erreur lors de la lecture : ", &e.to_string()].concat());
                break;
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    /* INIT */
    let listener = TcpListener::bind("127.0.0.1:7878")?;
    write_log("Serveur en écoute sur le port 7878".to_owned());
    let rsa_key_challenge = Arc::new(key_generation());
    let rsa_key_encryption = Arc::new(key_generation());

    write_db_id("server_challenge".to_owned(), &rsa_key_challenge, &rsa_key_encryption);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rsa_key_challenge_clone = Arc::clone(&rsa_key_challenge);
                let rsa_key_encryption_clone = Arc::clone(&rsa_key_encryption);
                thread::spawn(move || handle_client(stream, &rsa_key_challenge_clone, &rsa_key_encryption_clone));
            }
            Err(e) => {
                eprintln!("Erreur lors de la connexion : {}", e);
            }
        }
    }

    Ok(())
}
