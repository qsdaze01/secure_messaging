use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 512];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                // La connexion a été fermée
                break;
            }
            Ok(n) => {
                // Écrire les données reçues sur la sortie standard
                println!("Reçu : {}", String::from_utf8_lossy(&buffer[..n]));
                // Envoyer une réponse au client
                if let Err(e) = stream.write_all(b"Message recu\n") {
                    eprintln!("Erreur lors de l'envoi de la réponse : {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Erreur lors de la lecture : {}", e);
                break;
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7878")?;
    println!("Serveur en écoute sur le port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_client(stream));
            }
            Err(e) => {
                eprintln!("Erreur lors de la connexion : {}", e);
            }
        }
    }

    Ok(())
}
