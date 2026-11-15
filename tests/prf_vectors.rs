//! WebAuthn PRF quick-unlock vector (M5 C1): the v2 vector envelope with one
//! `webauthn-prf` slot for a FIXED synthetic PRF output and credential id.
//! Checked here with the core and independently by scripts/check-vectors.mjs
//! (Node/OpenSSL HKDF + XChaCha20-Poly1305), including the exact canonical
//! slot bytes. Synthetic and public. Regenerate only on purpose:
//! `cargo test --test prf_vectors -- --ignored generate`

use keymesh::keyslot::Authority;
use keymesh::rng::OsRandom;
use keymesh::vault::{prf_request, Vault};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BEFORE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v2/vectors.json"
);
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v2/prf.json");
const RP: &str = "keymesh.cloud";
const CRED: [u8; 20] = [0xc0; 20];
const PRF: [u8; 32] = [0x5a; 32];
const LABEL: &str = "Vector passkey";

fn auth_data(rp: &str, flags: u8) -> Vec<u8> {
    let mut d = Sha256::digest(rp.as_bytes()).to_vec();
    d.push(flags);
    d.extend_from_slice(&[0, 0, 0, 1]);
    d
}

fn load(p: &str) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
#[ignore = "writes the fixture file"]
fn generate() {
    let before = &load(BEFORE)["envelope"];
    let pw = before["password"].as_str().unwrap();
    let mut v = Vault::open_with_password(before["json"].as_str().unwrap().as_bytes(), pw).unwrap();
    let key = v.password_setup().unwrap().derive(pw).unwrap();
    let p = v
        .begin_prf(Authority::PasswordKey(&key), &mut OsRandom)
        .unwrap();
    v.add_prf_slot(
        Authority::PasswordKey(&key),
        &p,
        &CRED,
        RP,
        false,
        LABEL,
        &PRF,
        &mut OsRandom,
    )
    .unwrap();
    let (bytes, _) = v.seal_next_protected(&mut OsRandom).unwrap();
    let out = json!({
        "note": "Synthetic, public PRF quick-unlock vector (fixed PRF output). Not secrets.",
        "before": "vectors.json#envelope",
        "prf": {
            "json": String::from_utf8(bytes).unwrap(),
            "password": pw,
            "credential_id_hex": data_encoding::HEXLOWER.encode(&CRED),
            "prf_output_hex": data_encoding::HEXLOWER.encode(&PRF),
            "rp_id": RP,
            "label": LABEL,
            "titles": before["titles"],
        },
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}

#[test]
fn prf_vector_opens_only_with_the_matching_assertion() {
    let f = load(PATH);
    let e = &f["prf"];
    let b = e["json"].as_str().unwrap().as_bytes();
    let ok = Vault::open_with_prf(b, &CRED, &auth_data(RP, 0x05), &PRF, RP).unwrap();
    assert_eq!(ok.len(), e["titles"].as_array().unwrap().len());
    assert!(Vault::open_with_password(b, e["password"].as_str().unwrap()).is_ok());
    let mut wrong = PRF;
    wrong[0] ^= 1;
    assert!(Vault::open_with_prf(b, &CRED, &auth_data(RP, 0x05), &wrong, RP).is_err());
    assert!(Vault::open_with_prf(b, &CRED, &auth_data(RP, 0x01), &PRF, RP).is_err());
    let req = prf_request(b).unwrap();
    assert_eq!(req.len(), 1);
    assert_eq!(req[0].label, LABEL);
    // The original vector (no PRF slot) does not open with it.
    let before = load(BEFORE);
    let ob = before["envelope"]["json"].as_str().unwrap().as_bytes();
    assert!(Vault::open_with_prf(ob, &CRED, &auth_data(RP, 0x05), &PRF, RP).is_err());
}
