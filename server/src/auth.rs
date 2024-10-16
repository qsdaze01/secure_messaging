use std::{net::TcpStream, vec};

use num_bigint::BigUint;

use crate::{challenge::{create_challenge, get_challenge}, identify_db::write_db_id, log::write_log, rsaes_oaep::RsaKey, send_receive::{receive, send}, sessions_information::{get_session_number, write_sessions_information}, utils::{biguint_to_hex_string, challenge_generation, hex_string_to_biguint, hex_string_to_bytes, key_generation_aes_128, utf8_to_hex_string, vec_u8_to_hex_string}};

pub fn auth_client(stream: &mut TcpStream, server_challenge_key: &RsaKey, server_encryption_key: &RsaKey) -> bool{
    let mut buffer = [0; 8192];

    send(&mut hex_string_to_bytes(&utf8_to_hex_string("Start auth")).to_vec(), stream);

    receive(&mut buffer, stream);

    let binding: String = vec_u8_to_hex_string(buffer.to_vec());

    let size_id:usize = binding.chars().nth(0).unwrap().to_digit(10).unwrap().try_into().unwrap();

    println!("{:#?}", binding.chars().nth(0));

    let client_rsa_challenge = RsaKey {
        private_key: BigUint::from(0u32),
        public_key: (hex_string_to_biguint(&binding.chars().skip(1+size_id).take(512).collect::<String>()), hex_string_to_biguint(&binding.chars().skip(1+size_id+512).take(5).collect::<String>())),
    };
    println!("ID : {:#?}", binding.chars().skip(1).take(size_id).collect::<String>());
    println!("{:#?}", client_rsa_challenge.public_key.0);
    println!("{:#?}", client_rsa_challenge.public_key.1);
    
    println!("Before creation challenge");
    let mut challenge = vec![0; 32];
    challenge_generation(&mut challenge);

    let rsa_challenge = create_challenge(&client_rsa_challenge, vec_u8_to_hex_string(challenge.clone()));
    
    println!("{:#?}", rsa_challenge);
    println!("Challenge created : {}", rsa_challenge.len());

    send(&mut hex_string_to_bytes(&rsa_challenge), stream);

    println!("Send OK");

    let mut buffer = [0; 8192];
    receive(&mut buffer, stream);

    println!("Buffer : {:#?}", buffer.to_vec());
    println!("Challenge : {:#?}", challenge.clone());

    if buffer.to_vec() != challenge.clone() {
        write_log("Authentication failed : wrong challenge client side".to_owned());
        return false;
    }

    send(&mut hex_string_to_bytes(&[&biguint_to_hex_string(server_challenge_key.public_key.0.clone()), "|", &biguint_to_hex_string(server_challenge_key.public_key.1.clone())].concat()), stream);

    let mut buffer = [0; 8192];

    receive(&mut buffer, stream);

    let decrypted_challenge = get_challenge(server_challenge_key, vec_u8_to_hex_string(buffer.to_vec()));

    send(&mut hex_string_to_bytes(&decrypted_challenge), stream);

    let mut buffer = [0; 8192];

    receive(&mut buffer, stream);

    let binding = vec_u8_to_hex_string(buffer.to_vec());
    let id_and_public_key = binding.split("|").collect::<Vec<&str>>();
    
    let client_rsa_encryption = RsaKey {
        private_key: BigUint::from(0u32),
        public_key: (hex_string_to_biguint(id_and_public_key[1]), hex_string_to_biguint(id_and_public_key[2])),
    };

    write_db_id(id_and_public_key[0].to_owned(), &client_rsa_challenge, &client_rsa_encryption);

    send(&mut hex_string_to_bytes(&[biguint_to_hex_string(server_encryption_key.public_key.0.clone()), "|".to_owned(), biguint_to_hex_string(server_encryption_key.public_key.1.clone())].concat()), stream);

    let mut buffer: [u8; 8192] = [0; 8192];

    receive(&mut buffer, stream);

    if buffer.len() != 16 {
        write_log("Error len key symmetric signature client".to_owned());
        return false;
    }

    let key_signature_client = vec_u8_to_hex_string(buffer.to_vec());

    let mut key_signature_server_vec = vec![0, 16];
    key_generation_aes_128(&mut key_signature_server_vec);
    let key_signature_server = vec_u8_to_hex_string(key_signature_server_vec.clone());

    send(&mut key_signature_server_vec, stream);

    let mut buffer: [u8; 8192] = [0; 8192];

    receive(&mut buffer, stream);

    if buffer.len() != 16 {
        write_log("Error len key symmetric encryption client".to_owned());
        return false;
    }

    let key_encryption_client = vec_u8_to_hex_string(buffer.to_vec());

    let mut key_encryption_server_vec = vec![0, 16];
    key_generation_aes_128(&mut key_encryption_server_vec);
    let key_encryption_server = vec_u8_to_hex_string(key_encryption_server_vec.clone());

    send(&mut key_encryption_server_vec, stream);

    let session_number = (get_session_number(id_and_public_key[0].to_owned()).parse::<usize>().unwrap() + 1).to_string();

    write_sessions_information(id_and_public_key[0].to_owned(), session_number, key_signature_client, key_encryption_client, key_signature_server, key_encryption_server);

    // Il faut rajouter un système de changement des clés symmétriques régulièrement entre le server et le client
    // Réussir à transmettre les clés symmétriques et asymétriques de clients à clients 

    return true;
}