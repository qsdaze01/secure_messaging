mod rsaes_oaep;
use rsaes_oaep::{emsa_pss_encode, key_generation, rsa_oaep_decrypt, rsa_oaep_encrypt, rsassa_pss_sign, rsassa_pss_verify, RsaMessage};

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
}
