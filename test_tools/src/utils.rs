use std::u8;

use num_bigint::{BigUint, RandBigInt};
use num_traits:: {One, Num};
use rand::Rng;

pub fn primality_test(p:&BigUint) -> bool {
    let s = [0, 1, 2];
    for _ in s {
        let big_int_two = BigUint::from(2u32);
        let big_int_one = BigUint::one();
        let a = rand::thread_rng().gen_biguint_range(&big_int_two,&(p.clone()-big_int_two.clone()));
        if a.clone().modpow(&(p.clone()-big_int_one.clone()), &p.clone()) != big_int_one.clone() {
            return false;
        }
    }
    return true;
}

pub fn gen_prime_number(size_number:u64) -> BigUint{
    let mut p = BigUint::ZERO;

    loop {
        let mut rng = rand::thread_rng();
        let temp_p = &mut p;
        let min_value = BigUint::from(40u32);
        loop {
            *temp_p = rng.gen_biguint(size_number);
            if *temp_p > min_value {
                break;
            }
        }
        let test_prime = primality_test(temp_p);
        if test_prime == true {
            break;
        }
    }

    return p;
}

pub fn hex_string_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len()/2);

    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => println!("Error convertion string to bytes"),
        }
    }

    return bytes;
}

pub fn xor_strings(s1: &str, s2: &str) -> Vec<u8> {
    let bytes1 = hex_string_to_bytes(s1);
    let bytes2 = hex_string_to_bytes(s2);
    let len = std::cmp::min(bytes1.len(), bytes2.len());
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(bytes1[i] ^ bytes2[i]);
    }
    result
}

pub fn hex_to_utf8_string(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    if hex.len() % 2 != 0 {
        return Err("La longueur de la chaîne hexadécimale doit être paire".into());
    }

    let mut bytes = Vec::new();

    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)?;
        bytes.push(byte);
    }

    let utf8_string = String::from_utf8(bytes)?;

    Ok(utf8_string)
}

pub fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

pub fn hex_string_to_biguint(hex: &str) -> BigUint {
    BigUint::from_str_radix(hex, 16).map_err(|e| format!("Erreur de conversion: {}", e)).expect("Erreur de conversion")
}

pub fn biguint_to_hex_string(num:BigUint) -> String {
    num.to_str_radix(16)
}

pub fn vec_u8_to_hex_string(vec: Vec<u8>) -> String {
    vec.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub fn last_n_chars(s: &str, n: usize) -> &str {
    let _char_count = s.chars().count();
    let start_index = s.char_indices()
                       .rev()
                       .nth(n - 1)
                       .map(|(idx, _)| idx)
                       .unwrap_or(0);
    &s[start_index..]
}

pub fn key_generation_aes_128(key:&mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    for i in 0..16 {
        key[i] = rng.gen_range(0..=255);
    }
}

