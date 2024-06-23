use chrono::{NaiveDateTime, Utc};
use std::io;
use crate::{cts_cbc::{decrypt_cts_cbc, encrypt_cts_cbc}, hmac::{check_hmac, compute_hmac}, utils::{hex_string_to_utf8, utf8_to_hex_string}};

#[derive(Debug)]
pub struct Message {
    pub destination : String,
    pub source : String,
    pub message : String,
    pub message_len : usize,
    pub timestamp : NaiveDateTime,
}

pub fn stringify_message_object(message: Message) -> String {
    return [message.destination, "|".to_owned(), message.source, "|".to_owned(), message.message, "|".to_owned(), message.message_len.to_string(), "|".to_owned(), message.timestamp.to_string()].concat();
}

pub fn receive_string_to_message_object(received_message: String) -> Message{
    let res = received_message.split("|").collect::<Vec<&str>>();

    let time_str = format!("{}", res[4]);
    let timestamp = NaiveDateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S%.f").expect("Erreur lors du parsing du timestamp");

    let message = Message{
        destination: res[0].to_owned(),
        source: res[1].to_owned(),
        message: res[2].to_owned(),
        message_len: res[3].to_owned().parse::<usize>().unwrap(),
        timestamp: timestamp,
    };
    return message;
}

pub fn get_message_to_send(destination: String, source: String, message:String, key_encryption:Vec<u8>, key_signature:String) -> String {
    let message_object = Message {
        destination: destination,
        source: source, 
        message: message.clone(), 
        message_len: message.len(),
        timestamp: Utc::now().naive_utc(),
    };
    let message_string = stringify_message_object(message_object);
    let message_hexa = utf8_to_hex_string(&message_string);
    let message_encrypted_and_iv = encrypt_cts_cbc(message_hexa, key_encryption);
    let signature = compute_hmac(key_signature, [message_encrypted_and_iv.0.clone(), message_encrypted_and_iv.1.clone()].concat());

    let message_final = [message_encrypted_and_iv.0, "|".to_owned(), message_encrypted_and_iv.1, "|".to_owned(), signature].concat();
    
    return message_final;
}

pub fn get_received_message(received_message: String, key_encryption:Vec<u8>, key_signature:String) -> Result<Message, io::Error> {
    let received_message_splitted = received_message.split("|").collect::<Vec<&str>>();
    let received_signature = received_message_splitted[2];
    let computed_signature = compute_hmac(key_signature, [received_message_splitted[0], received_message_splitted[1]].concat());

    if check_hmac(received_signature.to_owned(), computed_signature) {
        let decrypted_message = decrypt_cts_cbc(received_message_splitted[0].to_owned(), key_encryption, received_message_splitted[1].to_owned());
        let message_utf8 = hex_string_to_utf8(&decrypted_message);
        
        let mut _message_utf8 = match message_utf8 {
            Ok(message_utf8) => {let message_object = receive_string_to_message_object(message_utf8);
                return Ok(message_object);
            },
            Err(_e) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Error conversion to UTF-8")),
        };
        //let message_object = receive_string_to_message_object(message_utf8.unwrap());
        //Ok(message_object)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed"))
    }
}
