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

use std::sync::Arc;

use chrono::{DateTime, Utc};
use cts_cbc::{decrypt_cts_cbc, encrypt_cts_cbc};
use message::{get_message_to_send, get_received_message, receive_string_to_message_object};
use pbkdf2::compute_derivate_key;
use rsaes_oaep::{key_generation, rsa_oaep_decrypt, rsa_oaep_encrypt, rsassa_pss_sign, rsassa_pss_verify, RsaMessage};
use utils::{hex_string_to_utf8, utf8_to_hex_string, vec_u8_to_hex_string};
//use aes::{encrypt_aes, decrypt_aes, key_expansion_aes, display_block_aes};

fn main() {
    log::write_log("Start of the program".to_string());
    
    let now_utc: DateTime<Utc> = Utc::now();
    println!("Heure UTC actuelle : {}", now_utc);

    //let now_utc = OffsetDateTime::now_utc();
    //println!("L'heure actuelle en UTC est : {}", now_utc);
    
    //receive_string_to_message("a0gpdhfgiof|bgfdnibndfoib|jgidosbnjdofb|gfdsohugfo".to_owned());

    /*
    let key = key_generation();

    let message = RsaMessage {
        message: "wxcvbn".to_string(),
        length: 6,
    };

    identify_db::write_db_id("aaaaa".to_string(), &key);

    identify_db::find_db_id("aaaaa".to_string());

    let c = rsa_oaep_encrypt(&key, message, "azer".to_string());

    let m = rsa_oaep_decrypt(&key, c, "azer".to_string());

    println!("Message : {}", m);

    let message2 = RsaMessage {
        message: "wxcvbn".to_string(),
        length: 6,
    };

    let s = rsassa_pss_sign(&key, message2);

    let message3 = RsaMessage {
        message: "wxcvbn".to_string(),
        length: 6,
    };

    let test = rsassa_pss_verify(&key, message3, s);

    println!("Test : {}", test);

    //let mut block:[u8;16] = [0;16];
    //let round_key:[u8;176] = [0;176];
    */
    let mut key = vec![0;16];
    utils::key_generation_aes_128(&mut key);

    //for i in 0..16 {
    //    block[i] =  0x01;
    //}
    
    //key_expansion_aes(key.to_vec(), round_key.to_vec());
    //encrypt_aes(&mut block.to_vec(), round_key.to_vec());
    //decrypt_aes(&mut block.to_vec(), round_key.to_vec());
    //display_block_aes(block.to_vec());

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

    /*
    let key_hmac:[u8;32] = [0;32];

    utils::key_generation_hmac(&mut key_hmac.to_vec());

    let hmac = hmac::compute_hmac(utils::vec_u8_to_hex_string(key_hmac.to_vec()), "azertyuiop".to_string());

    println!("HMAC : {}", hmac);
    */
}
