use crate::utils::{self, vec_u8_to_hex_string};
use sha3::{Digest, Sha3_256};

pub fn compute_hmac(key:String, text:String) -> String {
    let mut ipad = Vec::new();
    for _ in vec![0; 32] {
        ipad.push(0x36u8);
    }

    let mut opad = Vec::new();
    for _ in vec![0; 32] {
        opad.push(0x5cu8);
    }

    let k0_xor_ipad = utils::vec_u8_to_hex_string(utils::xor_strings(&key, &utils::vec_u8_to_hex_string(ipad)));
    
    let temp = [k0_xor_ipad, text].concat();

    let mut hasher = Sha3_256::new();
    hasher.update(temp);
    let first_hash = hasher.finalize();

    let k0_xor_opad = utils::vec_u8_to_hex_string(utils::xor_strings(&key, &utils::vec_u8_to_hex_string(opad)));

    let temp2 = [k0_xor_opad, utils::vec_u8_to_hex_string(first_hash.to_vec())].concat();

    let mut hasher = Sha3_256::new();
    hasher.update(temp2);
    let hmac = hasher.finalize();

    return vec_u8_to_hex_string(hmac.to_vec());
}