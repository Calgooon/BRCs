//! The BRC-252 step program: proves one transaction's claim from its parents'
//! proofs. Inputs, in order: this program's verifying key digest, the raw
//! transaction, every parent raw, and the public values of each parent proof
//! the prover supplies (their proofs ride the proof input stream).

#![no_main]
sp1_zkvm::entrypoint!(main);

use bnt_step::{public_values, read_public_values, step, Parent};
use sha2::{Digest, Sha256};

pub fn main() {
    println!("cycle-tracker-start: read");
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let raw = sp1_zkvm::io::read_vec();
    let parents_raw = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let proven = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    println!("cycle-tracker-end: read");

    println!("cycle-tracker-start: claims");
    let mut claims = Vec::with_capacity(proven.len());
    for values in &proven {
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &Sha256::digest(values).into());
        let (made_under, claim) = read_public_values(values).expect("a parent proof commits a claim");
        assert_eq!(made_under, vkey, "a parent proof was made under another program");
        claims.push(claim);
    }
    println!("cycle-tracker-end: claims");
    println!("cycle-tracker-start: parents");
    let parents: Vec<Parent> = parents_raw.iter().map(|raw| Parent::parse(raw).expect("a parent parses")).collect();
    println!("cycle-tracker-end: parents");
    println!("cycle-tracker-start: step");
    let claim = step(&raw, &parents, &claims).expect("the step reads its transaction");
    println!("cycle-tracker-end: step");
    sp1_zkvm::io::commit_slice(&public_values(&vkey, &claim.encode()));
}
