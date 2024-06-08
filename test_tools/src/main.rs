mod rsaes_oaep;
mod aes;
pub mod utils;

use rsaes_oaep::{key_generation, rsa_oaep_decrypt, rsa_oaep_encrypt, rsassa_pss_sign, rsassa_pss_verify, RsaMessage};
use aes::{encrypt_aes, decrypt_aes, key_expansion_aes, display_block_aes};

fn main() {
    let key = key_generation();

    let message = RsaMessage {
        message: "wxcvbn".to_string(),
        length: 6,
    };

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

    let mut block:[u8;16] = [0;16];
    let round_key:[u8;176] = [0;176];
    
    let key:[u8;16] = [0;16];

    utils::key_generation_aes_128(&mut key.to_vec());

    for i in 0..16 {
        block[i] =  0x01;
    }
    
    key_expansion_aes(key.to_vec(), round_key.to_vec());
    encrypt_aes(block.to_vec(), round_key.to_vec());
    decrypt_aes(block.to_vec(), round_key.to_vec());
    display_block_aes(block.to_vec());
}
