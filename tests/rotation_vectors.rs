//! Data-key rotation vector (M5 B, ADR 0002 §8): the v2 vector envelope
//! (`tests/fixtures/v2/vectors.json`) rotated to a new password and recovery
//! code. Checked here with the core and independently by
//! `scripts/check-vectors.mjs` (Node/OpenSSL Argon2id, HKDF, XChaCha20-Poly1305).
//!
//! Synthetic and public. Regenerate only on purpose:
//! `cargo test --test rotation_vectors -- --ignored generate`

use keymesh::keyslot::{Authority, PasswordSetup};
use keymesh::recovery::RecoveryCode;
use keymesh::rng::OsRandom;
use keymesh::vault::Vault;
use serde_json::{json, Value};

const BEFORE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v2/vectors.json"
);
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v2/rotation.json"
);
const NEW_PASSWORD: &str = "synthetic rotation vector passphrase";

fn load(p: &str) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.items().map(|i| i.title.clone()).collect();
    t.sort();
    t
}

#[test]
#[ignore = "writes the fixture file"]
fn generate() {
    let before = &load(BEFORE)["envelope"];
    let bytes = before["json"].as_str().unwrap().as_bytes();
    let password = before["password"].as_str().unwrap();
    let mut v = Vault::open_with_password(bytes, password).unwrap();
    let cur = v.password_setup().unwrap().derive(password).unwrap();
    let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
    let new_key = setup.derive(NEW_PASSWORD).unwrap();
    let p = v
        .begin_rotation(
            Authority::PasswordKey(&cur),
            &setup,
            &new_key,
            &mut OsRandom,
        )
        .unwrap();
    let code = RecoveryCode::parse(&p.code().to_text()).unwrap();
    v = v.finish_rotation(&p, &code).unwrap();
    let (after, rev) = v.seal_next_protected(&mut OsRandom).unwrap();
    let out = json!({
        "note": "Synthetic, public rotation vector: vectors.json envelope rotated (new DEK, new slots). Not secrets.",
        "before": "vectors.json#envelope",
        "after": {
            "json": String::from_utf8(after).unwrap(),
            "password": NEW_PASSWORD,
            "recovery_code": code.to_text().as_str(),
            "vault_id": v.vault_id(),
            "revision": rev,
            "titles": titles(&v),
        },
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}

#[test]
fn rotated_vector_opens_only_with_the_new_credentials() {
    let before = &load(BEFORE)["envelope"];
    let after = &load(PATH)["after"];
    let (b, a) = (
        before["json"].as_str().unwrap().as_bytes(),
        after["json"].as_str().unwrap().as_bytes(),
    );
    let (old_pw, new_pw) = (
        before["password"].as_str().unwrap(),
        after["password"].as_str().unwrap(),
    );
    let old_code = RecoveryCode::parse(before["recovery_code"].as_str().unwrap()).unwrap();
    let new_code = RecoveryCode::parse(after["recovery_code"].as_str().unwrap()).unwrap();

    let ra = Vault::open_with_password(a, new_pw).unwrap();
    assert_eq!(ra.vault_id(), before["vault_id"].as_str().unwrap());
    assert_eq!(ra.revision(), after["revision"].as_u64().unwrap());
    assert_eq!(ra.revision(), before["revision"].as_u64().unwrap() + 1);
    let expected: Vec<String> = serde_json::from_value(after["titles"].clone()).unwrap();
    assert_eq!(titles(&ra), expected);
    assert_eq!(
        titles(&Vault::open_with_recovery(a, &new_code).unwrap()),
        expected
    );
    assert!(Vault::open_with_password(a, old_pw).is_err());
    assert!(Vault::open_with_recovery(a, &old_code).is_err());
    // The retained "backup" (before) keeps its own credentials only.
    assert_eq!(
        titles(&Vault::open_with_password(b, old_pw).unwrap()),
        expected
    );
    assert!(Vault::open_with_password(b, new_pw).is_err());
    assert!(Vault::open_with_recovery(b, &new_code).is_err());
    // Every ciphertext differs; item ids and revisions are kept.
    let (jb, ja): (Value, Value) = (
        serde_json::from_slice(b).unwrap(),
        serde_json::from_slice(a).unwrap(),
    );
    for (x, y) in jb["items"]
        .as_array()
        .unwrap()
        .iter()
        .zip(ja["items"].as_array().unwrap())
    {
        assert_eq!((&x["id"], &x["rev"]), (&y["id"], &y["rev"]));
        assert_ne!(x["sealed"], y["sealed"]);
    }
    for k in 0..2 {
        assert_ne!(jb["slots"][k]["id"], ja["slots"][k]["id"]);
    }
}
