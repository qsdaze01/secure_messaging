use std::{io::{Read, Write}, net::TcpStream};

use crate::log::write_log;

pub fn receive(buffer: &mut [u8], stream: &mut TcpStream) -> bool{
    match stream.read(buffer) {
        Ok(0) => {
            write_log("Close connexion".to_owned());
            return false;
        }
        Ok(n) => {
            write_log(["Received : ", &String::from_utf8_lossy(&buffer[..n])].concat());
            return true;
        }
        Err(e) => {
            write_log(["Erreur lors de la lecture : ", &e.to_string()].concat());
            return false;
        }
    }
}

pub fn send(buffer: &mut [u8], stream: &mut TcpStream) -> bool {
    if let Err(e) = stream.write_all(buffer) {
        write_log(["Erreur lors de l'envoi de la réponse : ", &e.to_string()].concat());
        return false;
    } else {
        write_log("Message envoyé".to_owned());
        return true;
    }
}
