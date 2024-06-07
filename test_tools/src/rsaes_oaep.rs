//use rand::thread_rng;
use num_bigint::{BigUint, RandBigInt};
use num_traits:: {One, Num};
use hex::{encode, decode};
use sha3::{Digest, Sha3_256};

pub struct RsaKey {
    private_key: BigUint,
    public_key: (BigUint, BigUint),
}

pub struct RsaMessage {
    pub message: String,
    pub length: usize,
}

fn primality_test(p:&BigUint) -> bool {
    let s = [0, 1, 2];
    for _ in s {
        let big_int_two = BigUint::from(2u32);
        let big_int_one = BigUint::one();
        let a = rand::thread_rng().gen_biguint_range(&big_int_two,&(p.clone()-big_int_two.clone()));
        if a.clone().modpow(&(p.clone()-big_int_one.clone()), &p.clone()) != big_int_one.clone() {
            //println!("Not prime, {}", i);
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
        //println!("Prime number ? : {}", temp_p);
        if test_prime == true {
            break;
        }
    }

    //println!("Prime number : {}", p);
    return p;
}

pub fn key_generation() -> RsaKey{
    let p = gen_prime_number(1024);
    let q = gen_prime_number(1024);
    let e = BigUint::from(65537u32);

    let n = p.clone()*q.clone();
    let phi_n = (p.clone()-BigUint::one())*(q.clone()-BigUint::one());
    let d = e.modinv(&phi_n).expect("Not invertible");

    let key = RsaKey {
        private_key: d,
        public_key: (n, e),
    };

    return key;
}

pub fn mgf(seed:BigUint, length:usize) -> String{
    let mut counter: usize = 0;

    let mut t_parts = Vec::new();
    let seed = seed.to_bytes_le();

    loop {
        let c = counter.to_le_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update([seed.clone(), c.to_vec()].concat());
        let hash = hasher.finalize();
        t_parts.push(encode(hash));
        counter = counter + 1;
        if counter > (((length as f64)*8.0/256.0).ceil()-1.0) as usize {
            break;
        }
    }    
    let t = t_parts.concat();
    return t.to_string()[..length*2].to_string();
}

fn hex_string_to_bytes(hex: &str) -> Vec<u8> {
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

fn xor_strings(s1: &str, s2: &str) -> Vec<u8> {
    let bytes1 = hex_string_to_bytes(s1);
    let bytes2 = hex_string_to_bytes(s2);
    let len = std::cmp::min(bytes1.len(), bytes2.len());
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(bytes1[i] ^ bytes2[i]);
    }
    result
}

fn hex_to_utf8_string(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Vérifiez que la longueur de la chaîne hexadécimale est paire
    if hex.len() % 2 != 0 {
        return Err("La longueur de la chaîne hexadécimale doit être paire".into());
    }

    // Créez un vecteur pour stocker les octets
    let mut bytes = Vec::new();

    // Convertissez chaque paire hexadécimale en un octet
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)?;
        bytes.push(byte);
    }

    // Convertissez les octets en une chaîne UTF-8
    let utf8_string = String::from_utf8(bytes)?;

    Ok(utf8_string)
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn hex_string_to_biguint(hex: &str) -> BigUint {
    // Utiliser from_str_radix pour convertir la chaîne hexadécimale en BigUint
    BigUint::from_str_radix(hex, 16).map_err(|e| format!("Erreur de conversion: {}", e)).expect("Erreur de conversion")
}

fn biguint_to_hex_string(num:BigUint) -> String {
    num.to_str_radix(16)
}

pub fn rsaep (key:&RsaKey, m:BigUint) -> BigUint{
    let c:BigUint = m.modpow(&key.public_key.1, &key.public_key.0);

    return c;
}

pub fn rsadp (key:&RsaKey, c:BigUint) -> BigUint {
    let m:BigUint = c.modpow(&key.private_key, &key.public_key.0);

    return m;
}

pub fn rsa_oaep_encrypt (key:&RsaKey, message:RsaMessage, label:String) -> String {
    if message.length > 2048/8 - 2*(256/8) - 2 {
        println!("Message too long !");
        let var_return:String ="".to_string();
        return var_return;
    }
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    let lhash = hasher.finalize();

    let lenght_ps = 2048/8 - message.length - 2*(256/8) - 2;

    let mut ps = Vec::new();
    for _i in vec![0; lenght_ps] {
        ps.push(0x0u8);
    }

    let one = "01";

    let db = [encode(lhash), encode(String::from_utf8(ps.clone()).expect("Cannot convert")), one.to_string()/*encode((*one).to_string())*/, encode(message.message)].concat();
    
    let mut rng = rand::thread_rng();
    let seed = rng.gen_biguint(256);

    let dbmask = mgf(seed.clone(), 2048/8-256/8-1);

    let masked_db = xor_strings(&db, &dbmask);
    let masked_db_string:String = xor_strings(&db, &dbmask).iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<_>>().concat().into();

    let seed_mask = mgf(hex_string_to_biguint(&masked_db_string), 32);

    let masked_seed:String = xor_strings(&seed.to_str_radix(16), &seed_mask).iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<_>>().concat().into();

    let em = [0x0.to_string(), 0x0.to_string(), masked_seed.clone(), masked_db_string.clone()].concat();

    let m = hex_string_to_biguint(&em);

    let c = rsaep(key, m);

    let c_hex = biguint_to_hex_string(c);

    println!("Encrypt : OK");

    return c_hex;
}

pub fn rsa_oaep_decrypt (key:&RsaKey, cipher_text:String, label:String) -> String {
    let c = hex_string_to_biguint(&cipher_text);

    let m = rsadp(key, c);

    let em = biguint_to_hex_string(m);

    let mut hasher = Sha3_256::new();
    hasher.update(label);
    let _lhash = hasher.finalize();

    let masked_seed = &em[0..(256/4)];

    let masked_db = &em[(256/4)..];

    let seed_mask = mgf(hex_string_to_biguint(masked_db), 32);

    let seed:String = xor_strings(masked_seed, &seed_mask).iter().map(|byte| format!("{:02x}", byte)).collect();

    let dbmask = mgf(hex_string_to_biguint(&String::from_utf8(seed.into()).expect("Error conversion")), 2048/8-256/8-1);
    
    let db:String = xor_strings(masked_db, &dbmask).iter().map(|byte| format!("{:02x}", byte)).collect();

    let db_without_hash = &db[256/4..];

    let mut iter:usize = 0;

    while db.chars().nth(256/4+iter).expect("Error char") == '0'{
        iter = iter + 1;
    }
    let m = hex_to_utf8_string(&db[256/4+iter+1..]).expect("Error conversion");
    
    println!("Decrypt : OK");

    return m.to_string();
}
