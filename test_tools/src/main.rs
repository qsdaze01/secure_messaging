pub mod rsaes_oaep;
pub mod aes;
pub mod utils;
pub mod hmac;
pub mod log;
pub mod challenge;
pub mod identify_db;
pub mod cts_cbc;
pub mod pbkdf2;
pub mod message;

use chrono::{DateTime, Utc};
use cts_cbc::{decrypt_cts_cbc, encrypt_cts_cbc};
use message::{get_message_to_send, get_received_message};
use pbkdf2::compute_derivate_key;
use utils::vec_u8_to_hex_string;

fn main() {
    log::write_log("Start of the program".to_string());
    
    let now_utc: DateTime<Utc> = Utc::now();
    println!("Heure UTC actuelle : {}", now_utc);

    let mut key = vec![0;16];
    utils::key_generation_aes_128(&mut key);

    let message_to_send = get_message_to_send("123456".to_owned(), "123456".to_owned(), "987654".to_owned(), key.clone(), vec_u8_to_hex_string(key.clone()));
    println!("Message to send : {}", message_to_send);
    let received_message = get_received_message(message_to_send, key.clone(), vec_u8_to_hex_string(key.clone()));
    println!("Received message : {:?}", received_message.unwrap());

    println!("Start key : {}", vec_u8_to_hex_string(key.clone()));
    let (ciphertext, iv) = encrypt_cts_cbc("1234567890".to_owned(), key.clone());
    println!("Ciphertext : {}", ciphertext);
    let receive_message = decrypt_cts_cbc(ciphertext, key.clone(), iv);
    println!("Received message : {}", receive_message);

    println!("Derivated key : {}", compute_derivate_key("4164afcd49179b12".to_string(), "49165084adec4561".to_string(), 5000, 128));

}
