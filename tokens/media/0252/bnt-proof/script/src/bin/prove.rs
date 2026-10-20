//! Proves the E2E experiment: the test token's mainnet split, then its merge,
//! whose proof verifies the split's inside it. Each proof is checked, saved to
//! `proofs/`, and its size and proving time go to `proofs/results.json` with
//! the verifying key BRC-252 pins.
//!
//!     cargo run --release --bin prove            # split, then merge
//!     cargo run --release --bin prove -- merge   # reuse proofs/split.proof
//!     cargo run --release --bin prove -- groth16 # reuse proofs/split.proof, wrap the merge
//!
//! The Groth16 wrap needs 16 GB of memory or more and Docker, or the sp1-sdk
//! `native-gnark` feature with Go and Clang.

use std::time::Instant;

use bnt_step::{public_values, Claim};
use serde_json::{json, Value};
use sp1_sdk::blocking::prelude::*;
use sp1_sdk::blocking::ProverClient;
use sp1_sdk::{SP1Proof, SP1VerifyingKey};

#[path = "../evidence.rs"]
mod evidence;
use evidence::{root, Evidence};

const STEP_ELF: Elf = include_elf!("bnt-step-program");

struct Made {
    proof: SP1ProofWithPublicValues,
    seconds: f64,
    bytes: u64,
}

fn prove<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    vk: &SP1VerifyingKey,
    e: &Evidence,
    role: &str,
    parents: &[(&SP1ProofWithPublicValues, &Claim)],
    expect: &Claim,
    groth16: bool,
) -> Made {
    let vkey = vk.hash_u32();
    let mut stdin = SP1Stdin::new();
    stdin.write(&vkey);
    stdin.write_vec(e.raw(role));
    stdin.write(&e.parents(role));
    stdin.write(&parents.iter().map(|(_, claim)| public_values(&vkey, &claim.encode())).collect::<Vec<_>>());
    for (proof, _) in parents {
        let SP1Proof::Compressed(inner) = &proof.proof else { panic!("parent proofs are compressed") };
        stdin.write_proof(*inner.clone(), vk.vk.clone());
    }

    let name = if groth16 { format!("{role}.groth16") } else { role.to_string() };
    println!("proving {name}…");
    let started = Instant::now();
    let request = client.prove(pk, stdin);
    let proof = if groth16 { request.groth16().run() } else { request.compressed().run() }.expect("the step proves");
    let seconds = started.elapsed().as_secs_f64();
    client.verify(&proof, vk, None).expect("the proof verifies");
    assert_eq!(proof.public_values.as_slice(), public_values(&vkey, &expect.encode()), "{role}: the proof commits the native claim");

    let path = root().join(format!("proofs/{name}.proof"));
    proof.save(&path).unwrap();
    let bytes = std::fs::metadata(&path).unwrap().len();
    println!("{name}: {seconds:.1} s, {bytes} bytes, verified");
    Made { proof, seconds, bytes }
}

fn main() {
    let mode = std::env::args().nth(1);
    let groth16 = mode.as_deref() == Some("groth16");
    let only_merge = groth16 || mode.as_deref() == Some("merge");
    std::fs::create_dir_all(root().join("proofs")).unwrap();
    let e = Evidence::load();
    let split_claim = e.claim("split", &[]);
    let merge_claim = e.claim("merge", &[split_claim.clone()]);

    let client = ProverClient::builder().cpu().build();
    let started = Instant::now();
    let pk = client.setup(STEP_ELF).expect("setup");
    let vk = pk.verifying_key().clone();
    println!("setup {:.1} s, key {}", started.elapsed().as_secs_f64(), vk.bytes32());

    let split = if only_merge {
        let proof = SP1ProofWithPublicValues::load(root().join("proofs/split.proof")).expect("prove the split first");
        client.verify(&proof, &vk, None).expect("the saved split proof verifies under this key");
        let bytes = std::fs::metadata(root().join("proofs/split.proof")).unwrap().len();
        Made { proof, seconds: f64::NAN, bytes }
    } else {
        prove(&client, &pk, &vk, &e, "split", &[], &split_claim, false)
    };
    let merge = prove(&client, &pk, &vk, &e, "merge", &[(&split.proof, &split_claim)], &merge_claim, groth16);

    let results = root().join("proofs/results.json");
    if groth16 {
        let mut result: Value = serde_json::from_str(&std::fs::read_to_string(&results).expect("compressed results first")).unwrap();
        assert_eq!(result["vkey"].as_str(), Some(vk.bytes32().as_str()), "the compressed proofs were made under this key");
        result["groth16"] = json!({ "txid": e.0["txs"]["merge"]["txid"], "seconds": merge.seconds, "bytes": merge.bytes, "verifies": "split" });
        std::fs::write(&results, serde_json::to_string_pretty(&result).unwrap() + "\n").unwrap();
        println!("{result:#}");
        return;
    }

    let result = json!({
        "sp1": merge.proof.sp1_version,
        "vkey": vk.bytes32(),
        "mode": "compressed",
        "split": { "txid": e.0["txs"]["split"]["txid"], "seconds": split.seconds, "bytes": split.bytes },
        "merge": { "txid": e.0["txs"]["merge"]["txid"], "seconds": merge.seconds, "bytes": merge.bytes, "verifies": "split" },
    });
    std::fs::write(&results, serde_json::to_string_pretty(&result).unwrap() + "\n").unwrap();
    println!("{result:#}");
}
