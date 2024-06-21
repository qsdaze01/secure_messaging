use crate::hmac::compute_hmac;

pub fn compute_derivate_key(passphrase:String, salt: String, nb_iteration: usize, size_key: usize) -> String{
    let mut u = [salt, size_key.to_string()].concat();
    for _ in 0..nb_iteration {
        u = compute_hmac(passphrase.clone(), u);
    }

    return u[..size_key/4].to_string();
}