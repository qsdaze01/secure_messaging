use crate::{aes::encrypt_aes, utils::{hex_string_to_bytes, iv_generation, vec_u8_to_hex_string, xor_strings}};

fn encrypt_cts_cbc_without_padding(message:Vec<u8>, key:Vec<u8>) -> (String, String) {
    let iv:[u8;16] = [0;16];
    iv_generation(&mut iv.to_vec());
    let nb_block = message.len()/16;
    let mut iterator = 0;
    let mut previous_block = iv.to_vec();

    let mut ciphertext= vec![0; message.len()];

    while iterator < nb_block {
        let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[iterator*16..iterator*16 + 15].to_vec()));
        encrypt_aes(&mut to_encrypt, key.clone());
        for i in 0..15 {
            ciphertext[i + iterator*16] = to_encrypt[i];
            previous_block[i] = to_encrypt[i];
        }
        iterator = iterator + 1;
    }
    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv.to_vec()));
}

fn encrypt_cts_cbc_with_padding(message:Vec<u8>, key:Vec<u8>, remind_bytes:usize) -> (String, String) {
    let iv:[u8;16] = [0;16];
    iv_generation(&mut iv.to_vec());
    let nb_block = message.len()/16;
    let mut iterator = 0;
    let mut previous_block = iv.to_vec();

    let mut ciphertext= vec![0; message.len()-remind_bytes];
    while iterator < nb_block-2 {
        let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[iterator*16..iterator*16 + 15].to_vec()));
        encrypt_aes(&mut to_encrypt, key.clone());
        for i in 0..15 {
            ciphertext[i + iterator*16] = to_encrypt[i];
            previous_block[i] = to_encrypt[i];
        }
        iterator = iterator + 1;
    }

    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[(nb_block-2)*16..(nb_block-2)*16 + 15].to_vec()));
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..15 {
        if i < 15-remind_bytes {
            ciphertext[i + (nb_block-1)*16] = to_encrypt[i];
        }
        previous_block[i] = to_encrypt[i];
    }

    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(message[(nb_block-1)*16..(nb_block-1)*16 + 15].to_vec()));
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..15 {
        ciphertext[i + (nb_block-2)*16] = to_encrypt[i];
        previous_block[i] = to_encrypt[i];
    }

    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv.to_vec()));
}

fn encrypt_cts_cbc_with_padding_length_1(message:Vec<u8>, key:Vec<u8>) -> (String, String) {
    let iv:[u8;16] = [0;16];
    iv_generation(&mut iv.to_vec());
    let mut ciphertext= vec![0; message.len()];
    let mut to_encrypt = xor_strings(&vec_u8_to_hex_string(iv.to_vec()), &vec_u8_to_hex_string(message[0..15].to_vec()));
    encrypt_aes(&mut to_encrypt, key.clone());
    for i in 0..15 {
        ciphertext[i] = to_encrypt[i];
    }
    return (vec_u8_to_hex_string(ciphertext), vec_u8_to_hex_string(iv.to_vec()));
}

fn decrypt_cts_cbc_without_padding(ciphertext:Vec<u8>, key:Vec<u8>, iv:String) -> String {
    let nb_block = ciphertext.len()/16;
    let mut iterator = 0;
    let mut previous_block = hex_string_to_bytes(&iv);

    let mut message= vec![0; ciphertext.len()];

    while iterator < nb_block {
        encrypt_aes(&mut ciphertext[iterator*16..iterator*16 + 15].to_vec(), key.clone());
        let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(ciphertext[iterator*16..iterator*16 + 15].to_vec()));
        for i in 0..15 {
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
        encrypt_aes(&mut ciphertext[iterator*16..iterator*16 + 15].to_vec(), key.clone());
        let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(ciphertext[iterator*16..iterator*16 + 15].to_vec()));
        for i in 0..15 {
            message[i + iterator*16] = to_decrypt[i];
            previous_block[i] = ciphertext[i + iterator*16];
        }
        iterator = iterator + 1;
    }

    encrypt_aes(&mut ciphertext[(nb_block-2)*16..(nb_block-2)*16 + 15].to_vec(), key.clone());
    let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(ciphertext[(nb_block-2)*16..(nb_block-2)*16 + 15].to_vec()));
    for i in 0..15 {
        if i < 15-remind_bytes {
            message[i + (nb_block-1)*16] = to_decrypt[i];
        }
        previous_block[i] = ciphertext[i + iterator*16];
    }
    
    encrypt_aes(&mut ciphertext[(nb_block-1)*16..(nb_block-1)*16 + 15].to_vec(), key.clone());
    let to_decrypt = xor_strings(&vec_u8_to_hex_string(previous_block.to_vec()), &vec_u8_to_hex_string(ciphertext[(nb_block-1)*16..(nb_block-1)*16 + 15].to_vec()));
    for i in 0..15 {
        message[i + (nb_block-2)*16] = to_decrypt[i];
        previous_block[i] = ciphertext[i + iterator*16];
    }

    return vec_u8_to_hex_string(message);
}

fn decrypt_cts_cbc_with_padding_length_1(ciphertext:Vec<u8>, key:Vec<u8>, iv:String) -> String {
    let mut message= vec![0; ciphertext.len()];

    encrypt_aes(&mut ciphertext[0..15].to_vec(), key.clone());
    let to_encrypt = xor_strings(&iv, &vec_u8_to_hex_string(ciphertext[0..15].to_vec()));
    for i in 0..15 {
        message[i] = to_encrypt[i];
    }
    return vec_u8_to_hex_string(ciphertext);
}

pub fn encrypt_cts_cbc(message:String, key:Vec<u8>) -> (String, String) {
    let vec_message = hex_string_to_bytes(&message);
    if vec_message.len()%16 == 0 {
        return encrypt_cts_cbc_without_padding(vec_message, key);
    } else {
        let remind_bytes = vec_message.len();
        let vec_message:Vec<u8> = [vec_message, vec![0; remind_bytes]].concat();
        if vec_message.len()/16 == 1 {
            return encrypt_cts_cbc_with_padding_length_1(vec_message, key);
        } else {
            return encrypt_cts_cbc_with_padding(vec_message, key, remind_bytes);
        }
    }
}

pub fn decrypt_cts_cbc(ciphertext:String, key:Vec<u8>, iv:String) -> String {
    let vec_ciphertext = hex_string_to_bytes(&ciphertext);
    if vec_ciphertext.len()%16 == 0 {
        return decrypt_cts_cbc_without_padding(vec_ciphertext, key, iv);
    } else {
        let remind_bytes = vec_ciphertext.len();
        let vec_message:Vec<u8> = [vec_ciphertext, vec![0; remind_bytes]].concat();
        if vec_message.len()/16 == 1 {
            return decrypt_cts_cbc_with_padding_length_1(vec_message, key, iv);
        } else {
            return decrypt_cts_cbc_with_padding(vec_message, key, remind_bytes, iv);
        }
    }
}
