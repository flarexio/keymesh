//! Synthetic-input Argon2id timing for choosing envelope v2 defaults.
//! `cargo run --release --example kdf_bench` (no secrets involved).

use std::time::Instant;

fn main() {
    let password = b"synthetic benchmark password";
    let salt = [0x5au8; 16];
    println!("m_mib\tt\tp\tmedian_ms\tmin_ms\tmax_ms");
    for m_mib in [19u32, 46, 64] {
        for t in [1u32, 2, 3] {
            for p in [1u32, 4] {
                let params = argon2::Params::new(m_mib * 1024, t, p, Some(32)).unwrap();
                let a = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    params,
                );
                let mut times = Vec::new();
                for _ in 0..5 {
                    let mut out = [0u8; 32];
                    let s = Instant::now();
                    a.hash_password_into(password, &salt, &mut out).unwrap();
                    times.push(s.elapsed().as_secs_f64() * 1000.0);
                    std::hint::black_box(out);
                }
                times.sort_by(|a, b| a.partial_cmp(b).unwrap());
                println!(
                    "{m_mib}\t{t}\t{p}\t{:.0}\t{:.0}\t{:.0}",
                    times[2], times[0], times[4]
                );
            }
        }
    }
}
