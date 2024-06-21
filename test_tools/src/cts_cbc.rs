use std::vec;

use crate::{aes::{decrypt_aes, encrypt_aes, key_expansion_aes}, utils::{hex_string_to_bytes, iv_generation, vec_u8_to_hex_string, xor_strings}};

fn encrypt_cts_cbc_without_padding(message:Vec<u8>, key:Vec<u8>) -> (String, String) {
    let mut iv = vec![0;16];
    iv_generation(&mut iv);
    let nb_block = message.len()/16;
    let mut iterator = 0;
    let mut previous_block = iv.clone();

    let mut ciphertext= vec![0; message.len()];

    while iterator < nb_block {
        let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[iterator*16..iterator*16 + 16].to_vec()));
        encrypt_aes(&mut to_encrypt, key.clone());
        for i in 0..16 {
            ciphertext[i + iterator*16] = to_encrypt[i];
            previous_block[i] = to_encrypt[i];
        }
        iterator = iterator + 1;
    }
    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv));
}

fn encrypt_cts_cbc_with_padding(message:Vec<u8>, key:Vec<u8>, remind_bytes:usize) -> (String, String) {
    let mut iv = vec![0;16];
    iv_generation(&mut iv);
    let nb_block = message.len()/16;
    let mut iterator = 0;
    let mut previous_block = iv.clone();
    let mut ciphertext= vec![0; message.len()-remind_bytes];
    while iterator < nb_block-2 {
        let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[iterator*16..iterator*16 + 16].to_vec()));
        encrypt_aes(&mut to_encrypt, key.clone());
        for i in 0..16 {
            ciphertext[i + iterator*16] = to_encrypt[i];
            previous_block[i] = to_encrypt[i];
        }
        iterator = iterator + 1;
    }
    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[(nb_block-2)*16..(nb_block-2)*16 + 16].to_vec()));
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..16 {
        if i < 16-remind_bytes {
            ciphertext[i + (nb_block-1)*16] = to_encrypt[i];
        }
        previous_block[i] = to_encrypt[i];
    }

    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[(nb_block-1)*16..(nb_block-1)*16 + 16].to_vec()));
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..16 {
        ciphertext[i + (nb_block-2)*16] = to_encrypt[i];
    }

    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv));
}

fn encrypt_cts_cbc_with_padding_length_1(message:Vec<u8>, key:Vec<u8>) -> (String, String) {
    let mut iv = vec![0;16];
    iv_generation(&mut iv);
    let mut ciphertext= vec![0; message.len()];
    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(iv.clone()), &vec_u8_to_hex_string(message[0..16].to_vec()));
    
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..16 {
        ciphertext[i] = to_encrypt[i];
    }
    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv));
}

fn decrypt_cts_cbc_without_padding(ciphertext:&mut Vec<u8>, key:Vec<u8>, iv:String) -> String {
    let nb_block = ciphertext.len()/16;
    let mut iterator = 0;
    let mut previous_block = hex_string_to_bytes(&iv);
    let mut message= vec![0; ciphertext.len()];

    while iterator < nb_block {
        let mut temp_ciphertext = ciphertext[iterator*16..iterator*16 + 16].to_vec();
        decrypt_aes(&mut temp_ciphertext, key.clone());
        let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(temp_ciphertext));
        for i in 0..16 {
            message[i + iterator*16] = to_decrypt[i];
            previous_block[i] = ciphertext[i + iterator*16];
        }
        iterator = iterator + 1;

    }
    return vec_u8_to_hex_string(message);
}

fn decrypt_cts_cbc_with_padding(ciphertext:Vec<u8>, key:Vec<u8>, remind_bytes:usize, iv:String) -> String {
    let nb_block = ciphertext.len()/16;
    let mut iterator = 0;
    let mut previous_block = hex_string_to_bytes(&iv);
    let mut message= vec![0; ciphertext.len()-remind_bytes];
    while iterator < nb_block-2 {
        let mut temp_ciphertext = ciphertext[iterator*16..iterator*16 + 16].to_vec();
        let restore_ciphertext = ciphertext[iterator*16..iterator*16 + 16].to_vec();
        decrypt_aes(&mut temp_ciphertext, key.clone());
        let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(temp_ciphertext.clone()));
        for i in 0..16 {
            message[i + iterator*16] = to_decrypt[i];
            previous_block[i] = restore_ciphertext[i];
        }
        iterator = iterator + 1;
    }

    let mut temp_ciphertext = ciphertext[(nb_block-2)*16..(nb_block-2)*16 + 16].to_vec();
    decrypt_aes(&mut temp_ciphertext, key.clone());
    let mut composite_ciphertext = [ciphertext[(nb_block-1)*16..(nb_block-1)*16 + 16 - remind_bytes].to_vec(), temp_ciphertext[16-remind_bytes..16].to_vec()].concat();
    let last_xor = xor_strings(&vec_u8_to_hex_string(composite_ciphertext.clone()), &vec_u8_to_hex_string(temp_ciphertext.clone()));
    decrypt_aes(&mut composite_ciphertext, key.clone());
    let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.clone()), &vec_u8_to_hex_string(composite_ciphertext.clone()));
    for i in 0..16 { 
        message[i + (nb_block-2)*16] = to_decrypt[i];
        if i < 16-remind_bytes {
            message[i + (nb_block-1)*16] = last_xor[i];
        }
    }
    return vec_u8_to_hex_string(message);
}

fn decrypt_cts_cbc_with_padding_length_1(ciphertext:Vec<u8>, key:Vec<u8>, remind_bytes:usize, iv:String) -> String {
    let mut message= vec![0; ciphertext.len()];

    let mut temp_ciphertext = ciphertext[0..16].to_vec();
    decrypt_aes(&mut temp_ciphertext, key.clone());
    let to_encrypt = xor_strings(&iv, &vec_u8_to_hex_string(temp_ciphertext));
    for i in 0..16 {
        message[i] = to_encrypt[i];
    }
    return vec_u8_to_hex_string(message[0..16-remind_bytes].to_vec());
}

pub fn encrypt_cts_cbc(message:String, key:Vec<u8>) -> (String, String) {
    let vec_message = hex_string_to_bytes(&message);

    let mut round_key = vec![0;176];
    key_expansion_aes(key, &mut round_key);
    if vec_message.len()%16 == 0 {
        return encrypt_cts_cbc_without_padding(vec_message, round_key);
    } else {
        let remind_bytes = 16 - vec_message.len()%16;
        let vec_message:Vec<u8> = [vec_message, vec![0; remind_bytes]].concat();
        if vec_message.len()/16 == 1 {
            println!("padding lenght 1 : {} {}", vec_message.len()/16, vec_message.len());
            return encrypt_cts_cbc_with_padding_length_1(vec_message, round_key);
        } else {
            println!("Normal : {} {}", vec_message.len()/16, vec_message.len());
            return encrypt_cts_cbc_with_padding(vec_message, round_key, remind_bytes);
        }
    }
}

pub fn decrypt_cts_cbc(ciphertext:String, key:Vec<u8>, iv:String) -> String {
    let mut vec_ciphertext = hex_string_to_bytes(&ciphertext);
    let mut round_key = vec![0;176];
    key_expansion_aes(key, &mut round_key);
    if vec_ciphertext.len()%16 == 0 {
        println!("without padding : {} {}", vec_ciphertext.len()/16, vec_ciphertext.len());
        return decrypt_cts_cbc_without_padding(&mut vec_ciphertext, round_key, iv);
    } else {
        let remind_bytes = 16 - vec_ciphertext.len()%16;
        let vec_ciphertext:Vec<u8> = [vec_ciphertext, vec![0; remind_bytes]].concat();
        if vec_ciphertext.len()/16 == 1 {
            println!("padding lenght 1 : {} {}", vec_ciphertext.len()/16, vec_ciphertext.len());
            return decrypt_cts_cbc_with_padding_length_1(vec_ciphertext, round_key, remind_bytes, iv);
        } else {
            println!("Normal : {} {}", vec_ciphertext.len()/16, vec_ciphertext.len());
            return decrypt_cts_cbc_with_padding(vec_ciphertext, round_key, remind_bytes, iv);
        }
    }
}
