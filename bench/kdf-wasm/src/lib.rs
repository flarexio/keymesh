use wasm_bindgen::prelude::*;

/// One Argon2id run on fixed synthetic input; returns the first output byte
/// so the work cannot be optimized away. Timing happens in JavaScript.
#[wasm_bindgen]
pub fn run(m_kib: u32, t: u32, p: u32) -> u8 {
    let params = argon2::Params::new(m_kib, t, p, Some(32)).unwrap();
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(b"synthetic benchmark password", &[0x5a; 16], &mut out)
        .unwrap();
    out[0]
}
