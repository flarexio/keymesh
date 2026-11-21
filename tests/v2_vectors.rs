//! Envelope v2 vectors shared by the native core and the browser build
//! (`apps/web/e2e/protected.spec.ts` checks the same file through WASM, and
//! `scripts/check-vectors.mjs` recomputes the KDF values with Node's
//! OpenSSL-backed Argon2id and HKDF, an independent implementation).
//!
//! All values are synthetic and public. Regenerate only when the format
//! changes on purpose: `cargo test --test v2_vectors -- --ignored generate`

use hkdf::Hkdf;
use keymesh::kdf::{self, fields, KdfParams};
use keymesh::model::{Item, ItemData, Login, SecureNote};
use keymesh::recovery::RecoveryCode;
use keymesh::rng::OsRandom;
use keymesh::secret::SecretString;
use keymesh::vault::{password_request, read_header, ProtectedSetup, Vault};
use serde_json::{json, Value};
use sha2::Sha256;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v2/vectors.json"
);
const VAULT_ID: &str = "00112233445566778899aabbccddeeff";

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}
fn unhex(s: &str) -> Vec<u8> {
    data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
}

/// HKDF-SHA256 per the spec text (docs/adr/0002), computed with the `hkdf`
/// crate directly rather than through `keymesh::kdf::slot_kek`.
fn spec_kek(
    ikm: &[u8],
    salt: Option<&[u8]>,
    kind: &str,
    vault_id: &str,
    slot_id: &str,
) -> [u8; 32] {
    let info = fields(&[
        b"keymesh.vault",
        b"2",
        b"kek",
        kind.as_bytes(),
        vault_id.as_bytes(),
        slot_id.as_bytes(),
    ]);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(&info, &mut out)
        .unwrap();
    out
}

fn load() -> Value {
    serde_json::from_slice(&std::fs::read(PATH).unwrap()).unwrap()
}

#[test]
#[ignore = "writes the fixture file"]
fn generate() {
    // A decomposed "é" checks NFC normalization end to end.
    let password = "synthetic vector cafe\u{301} passphrase";
    let salt = [0x24u8; 16];
    let params = KdfParams::DEFAULT;
    let argon = kdf::argon2id(password, &salt, params).unwrap();
    let secret: [u8; 32] = core::array::from_fn(|i| (0xa0 + i) as u8);
    let code = RecoveryCode::from_secret(secret);

    let setup = ProtectedSetup::generate(&mut OsRandom).unwrap();
    let key = setup.password.derive(password).unwrap();
    let (mut v, envelope_code) = Vault::create_protected(&setup, &key, &mut OsRandom).unwrap();
    v.confirm_recovery(&envelope_code).unwrap();
    let note = ItemData::SecureNote(SecureNote {
        body: SecretString::new("SYNTHETIC-VECTOR-BODY"),
    });
    let login = ItemData::Login(Login {
        username: Some("vector@example.invalid".into()),
        password: Some(SecretString::new("SYNTHETIC-VECTOR-PW")),
        urls: vec![],
        totp_item: None,
        recovery_codes: vec![],
    });
    v.insert(Item::new("Vector note", note, &mut OsRandom).unwrap())
        .unwrap();
    v.insert(Item::new("Vector login", login, &mut OsRandom).unwrap())
        .unwrap();
    let (envelope, _) = v.seal_next_protected(&mut OsRandom).unwrap();

    let out = json!({
        "note": "Synthetic, public test vectors for keymesh.vault v2. Not secrets.",
        "argon2id": {
            "password": password, "salt_hex": hex(&salt),
            "m_kib": params.m_kib, "t": params.t, "p": params.p,
            "output_hex": hex(&argon[..]),
        },
        "kek": {
            "password": {
                "ikm_hex": hex(&argon[..]), "vault_id": VAULT_ID, "slot_id": "0123456789abcdef",
                "kek_hex": hex(&spec_kek(&argon[..], None, "password", VAULT_ID, "0123456789abcdef")),
            },
            "recovery": {
                "ikm_hex": hex(&secret), "salt_hex": hex(&salt), "vault_id": VAULT_ID, "slot_id": "fedcba9876543210",
                "kek_hex": hex(&spec_kek(&secret, Some(&salt), "recovery", VAULT_ID, "fedcba9876543210")),
            },
        },
        "recovery_code": { "secret_hex": hex(&secret), "text": code.to_text().as_str() },
        "envelope": {
            "json": String::from_utf8(envelope).unwrap(),
            "password": password,
            "recovery_code": envelope_code.to_text().as_str(),
            "vault_id": v.vault_id(),
            "revision": 1,
            "titles": ["Vector login", "Vector note"],
        },
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}

#[test]
fn argon2id_and_kek_vectors() {
    let j = load();
    let a = &j["argon2id"];
    let params = KdfParams {
        m_kib: a["m_kib"].as_u64().unwrap() as u32,
        t: a["t"].as_u64().unwrap() as u32,
        p: a["p"].as_u64().unwrap() as u32,
    };
    assert_eq!(params, KdfParams::DEFAULT, "vectors use the stored default");
    let out = kdf::argon2id(
        a["password"].as_str().unwrap(),
        &unhex(a["salt_hex"].as_str().unwrap()),
        params,
    )
    .unwrap();
    assert_eq!(hex(&out[..]), a["output_hex"]);
    // NFC: the precomposed spelling derives the same key.
    let composed = a["password"]
        .as_str()
        .unwrap()
        .replace("e\u{301}", "\u{e9}");
    let out2 = kdf::argon2id(&composed, &unhex(a["salt_hex"].as_str().unwrap()), params).unwrap();
    assert_eq!(out[..], out2[..]);
    for (kind, salt) in [
        ("password", None),
        ("recovery", j["kek"]["recovery"]["salt_hex"].as_str()),
    ] {
        let k = &j["kek"][kind];
        let salt = salt.map(unhex);
        let got = spec_kek(
            &unhex(k["ikm_hex"].as_str().unwrap()),
            salt.as_deref(),
            kind,
            k["vault_id"].as_str().unwrap(),
            k["slot_id"].as_str().unwrap(),
        );
        assert_eq!(hex(&got), k["kek_hex"]);
    }
}

#[test]
fn recovery_code_vector() {
    let j = load();
    let r = &j["recovery_code"];
    let secret: [u8; 32] = unhex(r["secret_hex"].as_str().unwrap()).try_into().unwrap();
    let code = RecoveryCode::from_secret(secret);
    assert_eq!(code.to_text().as_str(), r["text"]);
    assert!(RecoveryCode::parse(r["text"].as_str().unwrap())
        .unwrap()
        .ct_eq(&code));
}

#[test]
fn envelope_vector_opens_with_both_slots() {
    let j = load();
    let e = &j["envelope"];
    let bytes = e["json"].as_str().unwrap().as_bytes();
    let h = read_header(bytes).unwrap();
    assert_eq!(h.version, 2);
    assert_eq!(h.vault_id, e["vault_id"]);
    assert_eq!(
        password_request(bytes).unwrap().setup.params,
        KdfParams::DEFAULT
    );
    let by_pw = Vault::open_with_password(bytes, e["password"].as_str().unwrap()).unwrap();
    let code = RecoveryCode::parse(e["recovery_code"].as_str().unwrap()).unwrap();
    let by_rc = Vault::open_with_recovery(bytes, &code).unwrap();
    for v in [by_pw, by_rc] {
        let mut titles: Vec<_> = v.items().map(|i| i.title.clone()).collect();
        titles.sort();
        assert_eq!(serde_json::json!(titles), e["titles"]);
        assert_eq!(v.revision(), 1);
    }
    assert!(Vault::open_with_password(bytes, "synthetic wrong passphrase").is_err());
}
