use std::io::{self, Write, Read};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    println!("Connecté au serveur");

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
