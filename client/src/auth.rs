use std::{net::TcpStream, vec};

use num_bigint::BigUint;

use crate::{challenge::{create_challenge, get_challenge}, identify_db::write_db_id, log::write_log, rsaes_oaep::RsaKey, send_receive::{receive, send}, sessions_information::{get_session_number, write_sessions_information}, utils::{biguint_to_hex_string, challenge_generation, hex_string_to_biguint, hex_string_to_bytes, key_generation_aes_128, utf8_to_hex_string, vec_u8_to_hex_string}};

pub fn auth_self(stream: &mut TcpStream, id: String, client_challenge_key: &RsaKey, client_encryption_key: &RsaKey) -> bool {
    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);

    if vec_u8_to_hex_string(buffer[..10].to_vec()) != utf8_to_hex_string("Start auth") {
        write_log("Authentication failed : authentication did not start".to_string());
        return false;
    }
    
    let id_to_send = id.clone();
    let pub_key_0_to_send = biguint_to_hex_string(client_challenge_key.public_key.0.clone());
    let pub_key_1_to_send = biguint_to_hex_string(client_challenge_key.public_key.1.clone());

    println!("len id : {}", id_to_send.len().to_string());
    println!("len key 0 : {}", pub_key_0_to_send.len());
    println!("len key 1 : {}", pub_key_1_to_send.len());

    send(&mut hex_string_to_bytes(&[id_to_send.len().to_string(), id_to_send.clone(), pub_key_0_to_send.clone(), pub_key_1_to_send.clone()].concat()), stream);

    println!("Key 1 : {:#?}", client_challenge_key.public_key.0);
    println!("Key 2 : {:#?}", client_challenge_key.public_key.1);

    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);
    println!("Receive OK");
    let decrypted_challenge = get_challenge(client_challenge_key, vec_u8_to_hex_string(buffer.to_vec()));
    println!("Challenge decrypted");
    send(&mut hex_string_to_bytes(&('0'.to_string() + &decrypted_challenge)), stream);

    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);

    let binding = vec_u8_to_hex_string(buffer.to_vec());
    let id_and_public_key = binding.split("|").collect::<Vec<&str>>();
    
    let server_rsa_challenge = RsaKey {
        private_key: BigUint::from(0u32),
        public_key: (hex_string_to_biguint(id_and_public_key[1]), hex_string_to_biguint(id_and_public_key[2])),
    };

    let mut challenge = vec![0, 32];
    challenge_generation(&mut challenge);

    let rsa_challenge = create_challenge(&server_rsa_challenge, vec_u8_to_hex_string(challenge.clone()));
    
    send(&mut hex_string_to_bytes(&rsa_challenge), stream);

    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);

    if buffer.to_vec() != challenge.clone() {
        write_log("Authentication failed : wrong challenge server side".to_owned());
        return false;
    }

    send(&mut hex_string_to_bytes(&[&biguint_to_hex_string(client_encryption_key.public_key.0.clone()), "|", &biguint_to_hex_string(client_encryption_key.public_key.1.clone())].concat()), stream);

    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);

    let binding = vec_u8_to_hex_string(buffer.to_vec());
    let id_and_public_key = binding.split("|").collect::<Vec<&str>>();
    
    let server_rsa_encryption = RsaKey {
        private_key: BigUint::from(0u32),
        public_key: (hex_string_to_biguint(id_and_public_key[1]), hex_string_to_biguint(id_and_public_key[2])),
    };

    write_db_id(id.clone(), &server_rsa_challenge, &server_rsa_encryption);

    let mut key_signature_client_vec = vec![0, 16];
    key_generation_aes_128(&mut key_signature_client_vec);
    let key_signature_client = vec_u8_to_hex_string(key_signature_client_vec.clone());

    send(&mut key_signature_client_vec, stream);

    let mut buffer: [u8; 8192] = [0; 8192];
    receive(&mut buffer, stream);

    if buffer.len() != 16 {
        write_log("Error len key symmetric signature client".to_owned());
        return false;
    }
    let key_signature_server = vec_u8_to_hex_string(buffer.to_vec());

    let mut key_encryption_client_vec = vec![0, 16];
    key_generation_aes_128(&mut key_encryption_client_vec);
    let key_encryption_client = vec_u8_to_hex_string(key_encryption_client_vec.clone());

    send(&mut key_encryption_client_vec, stream);

    let mut buffer: [u8; 8192] = [0; 8192];
    receive(&mut buffer, stream);

    if buffer.len() != 16 {
        write_log("Error len key symmetric signature client".to_owned());
        return false;
    }
    let key_encryption_server = vec_u8_to_hex_string(buffer.to_vec());

    let session_number = (get_session_number(id.to_owned()).parse::<usize>().unwrap() + 1).to_string();

    write_sessions_information(id.to_owned(), session_number, key_signature_client, key_encryption_client, key_signature_server, key_encryption_server);

    return true;
}