fn main() {
    use aes_siv::{Aes128SivAead, Nonce, aead::{Aead, KeyInit, Payload}};
    
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let aad = b"test aad data here";
    
    let cipher = Aes128SivAead::new((&key).into());
    match cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &[], aad }) {
        Ok(ct) => {
            println!("encrypt empty PT: {} bytes = {}", ct.len(), ct.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""));
            // Try decrypt
            match cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad }) {
                Ok(pt) => println!("decrypt OK: {} bytes plaintext", pt.len()),
                Err(e) => println!("decrypt FAIL: {e:?}"),
            }
        }
        Err(e) => println!("encrypt FAIL: {e:?}"),
    }
}
