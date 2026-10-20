//! Checks the published step proofs: the published program binary has the key
//! `proofs/results.json` names, each proof verifies under that key, commits the
//! claim the plain-Rust step computes from the pinned mainnet transactions, and
//! has the size `results.json` reports.
//!
//!     cargo run --release --bin verify

use bnt_step::public_values;
use serde_json::Value;
use sp1_sdk::blocking::prelude::*;
use sp1_sdk::blocking::ProverClient;

#[path = "../evidence.rs"]
mod evidence;
use evidence::{root, Evidence};

const SOURCE_ELF: Elf = include_elf!("bnt-step-program");

fn main() {
    let results: Value = serde_json::from_str(&std::fs::read_to_string(root().join("proofs/results.json")).unwrap()).unwrap();
    let published = std::fs::read(root().join("proofs/bnt-step-program.elf")).expect("the published program binary");
    println!("program built from this source is byte-identical to the published binary: {}", *SOURCE_ELF == published[..]);

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(published)).expect("setup");
    let vk = pk.verifying_key();
    assert_eq!(results["vkey"].as_str(), Some(vk.bytes32().as_str()), "the published binary has the published key");
    println!("key {}", vk.bytes32());

    let e = Evidence::load();
    let vkey = vk.hash_u32();
    let split = e.claim("split", &[]);
    let merge = e.claim("merge", &[split.clone()]);

    for (file, role, claim, entry) in [
        ("split.proof", "split", &split, "split"),
        ("merge.proof", "merge", &merge, "merge"),
        ("merge.groth16.proof", "merge", &merge, "groth16"),
    ] {
        let path = root().join("proofs").join(file);
        if !path.exists() && entry == "groth16" {
            println!("{file}: not made yet");
            continue;
        }
        let proof = SP1ProofWithPublicValues::load(&path).unwrap();
        client.verify(&proof, vk, None).unwrap_or_else(|err| panic!("{file} verifies: {err}"));
        assert_eq!(proof.public_values.as_slice(), public_values(&vkey, &claim.encode()), "{file} commits the {role} claim");
        assert_eq!(results[entry]["txid"], e.0["txs"][role]["txid"], "{file} is the proof of the {role}");
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert_eq!(results[entry]["bytes"].as_u64(), Some(bytes), "{file} has the size results.json reports");
        println!("{file}: verifies, commits the {role} claim, {bytes} bytes");
    }
}
