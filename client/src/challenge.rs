use crate::rsaes_oaep;

pub fn create_challenge(key:&rsaes_oaep::RsaKey, r:String) -> String {
    let message = rsaes_oaep::RsaMessage {
        message: r,
        length: 32,
    };
    let c = rsaes_oaep::rsa_oaep_encrypt(key, message, "".to_string());

    return c;
}

pub fn get_challenge(key:&rsaes_oaep::RsaKey, c:String) -> String {
    let m = rsaes_oaep::rsa_oaep_decrypt(key, c, "".to_string());

    return m;
}

