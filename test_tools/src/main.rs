mod rsaes_oaep;
use rsaes_oaep::{key_generation, RsaMessage, rsa_oaep_encrypt, rsa_oaep_decrypt};

fn main() {
    let key = key_generation();

    let message = RsaMessage {
        message: "wxcvbn".to_string(),
        length: 6,
    };

    let c = rsa_oaep_encrypt(&key, message, "azer".to_string());

    let _m = rsa_oaep_decrypt(&key, c, "azer".to_string());
}
