//! Runs the step program in SP1 without proving and reports its cycles, for a
//! transfer and for a merge of sixteen branches. Parent proofs are not checked
//! here: their cost lands in recursion, not in the program's cycles.
//!
//!     cargo run --release

use bnt_step::script::{encode, Clause, Output, Rules};
use bnt_step::tx::{asset_id, txid, Tx, TxIn, TxOut, Txid};
use bnt_step::{public_values, read_public_values, step, Claim, Parent};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, SP1Stdin};

const STEP_ELF: Elf = include_elf!("bnt-step-program");
const VKEY: [u32; 8] = [7; 8];

fn key(n: u32) -> [u8; 33] {
    let mut k = [0x11; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_le_bytes());
    k
}

fn clause(n: u32) -> Clause {
    Clause { holder: key(n), rules: Rules::Open }
}

/// `{"v": 1, "iss": <key>, "mode": "open"}`
fn payload() -> Vec<u8> {
    let mut p = vec![0xa3, 0x61, b'v', 0x01, 0x63, b'i', b's', b's', 0x58, 0x21];
    p.extend(key(0));
    p.extend([0x64, b'm', b'o', b'd', b'e', 0x64, b'o', b'p', b'e', b'n']);
    p
}

fn input(prev: Txid, vout: u32) -> TxIn {
    let mut script = vec![72];
    script.extend([0x30; 72]);
    TxIn { prev_txid: prev, prev_vout: vout, script, sequence: u32::MAX }
}

fn p2pkh(n: u32) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend(&key(n)[..20]);
    s.extend([0x88, 0xac]);
    s
}

fn coin(n: u32) -> Tx {
    Tx {
        version: 1,
        inputs: vec![input([n as u8; 32], 0)],
        outputs: vec![TxOut { satoshis: 1000, script: p2pkh(n) }],
        locktime: 0,
    }
}

struct Proven {
    raw: Vec<u8>,
    claim: Claim,
}

/// Steps `tx` natively, then runs the program on the same inputs and checks it commits the same claim.
fn run(client: &impl Prover, label: &str, tx: &Tx, token_parents: &[&Proven], fee: &Tx) -> Proven {
    let raw = tx.encode();
    let mut parents_raw: Vec<Vec<u8>> = token_parents.iter().map(|p| p.raw.clone()).collect();
    parents_raw.push(fee.encode());
    let parents: Vec<Parent> = parents_raw.iter().map(|r| Parent::parse(r).unwrap()).collect();
    let claims: Vec<Claim> = token_parents.iter().map(|p| p.claim.clone()).collect();
    let claim = step(&raw, &parents, &claims).unwrap();

    let proven: Vec<Vec<u8>> = token_parents.iter().map(|p| public_values(&VKEY, &p.claim.encode())).collect();
    let mut stdin = SP1Stdin::new();
    stdin.write(&VKEY);
    stdin.write_vec(raw.clone());
    stdin.write(&parents_raw);
    stdin.write(&proven);
    let (output, report) = client.execute(STEP_ELF, stdin).deferred_proof_verification(false).run().unwrap();
    let (_, committed) = read_public_values(output.as_slice()).unwrap();
    assert_eq!(committed.encode(), claim.encode(), "{label}: the program and the native step agree");
    println!("{label:<28} {:>4} {:>12}", token_parents.len(), report.total_instruction_count());
    println!("{:?}", report.cycle_tracker);
    Proven { raw, claim }
}

fn main() {
    let client = ProverClient::builder().cpu().build();
    let funding = coin(0);
    let deploy = Tx {
        version: 1,
        inputs: vec![input(txid(&funding.encode()), 0)],
        outputs: vec![TxOut {
            satoshis: 1,
            script: encode(&Output::Deploy { supply: 1_000_000, payload: payload(), clause: clause(1) }).unwrap(),
        }],
        locktime: 0,
    };
    let deploy_raw = deploy.encode();
    let asset = asset_id(&txid(&deploy_raw), 0).unwrap();
    let deploy = Proven { claim: Claim { txid: txid(&deploy_raw), assets: vec![] }, raw: deploy_raw };

    let held = |amount: u64, holder: u32| encode(&Output::Held { asset, amount, clause: clause(holder) }).unwrap();
    let transfer = |prev: &Proven, vout: u32, fee: &Tx, outs: Vec<TxOut>| Tx {
        version: 1,
        inputs: vec![input(txid(&prev.raw), vout), input(txid(&fee.encode()), 0)],
        outputs: outs,
        locktime: 0,
    };

    println!("{:<28} {:>4} {:>12}", "step", "in", "cycles");
    let fee = coin(1);
    let first = transfer(&deploy, 0, &fee, vec![
        TxOut { satoshis: 1, script: held(1_000_000, 2) },
        TxOut { satoshis: 800, script: p2pkh(1) },
    ]);
    let first = run(&client, "first transfer from deploy", &first, &[&deploy], &fee);

    let fee = coin(2);
    let next = transfer(&first, 0, &fee, vec![
        TxOut { satoshis: 1, script: held(1_000_000, 3) },
        TxOut { satoshis: 800, script: p2pkh(2) },
    ]);
    let next = run(&client, "transfer", &next, &[&first], &fee);

    let width = 16u32;
    let fee = coin(3);
    let outs = (0..width).map(|i| TxOut { satoshis: 1, script: held(1_000_000 / width as u64, 100 + i) }).collect();
    let split = transfer(&next, 0, &fee, outs);
    let split = run(&client, "split into 16", &split, &[&next], &fee);

    let branches: Vec<Proven> = (0..width)
        .map(|b| {
            let fee = coin(10 + b);
            let tx = transfer(&split, b, &fee, vec![TxOut { satoshis: 1, script: held(1_000_000 / width as u64, 200 + b) }]);
            let raw = tx.encode();
            let mut parents = vec![Parent::parse(&split.raw).unwrap()];
            let fee_raw = fee.encode();
            parents.push(Parent::parse(&fee_raw).unwrap());
            let claim = step(&raw, &parents, &[split.claim.clone()]).unwrap();
            Proven { raw, claim }
        })
        .collect();
    let fee = coin(99);
    let merge = Tx {
        version: 1,
        inputs: branches.iter().map(|b| input(txid(&b.raw), 0)).chain([input(txid(&fee.encode()), 0)]).collect(),
        outputs: vec![TxOut { satoshis: 1, script: held(1_000_000, 7) }],
        locktime: 0,
    };
    let refs: Vec<&Proven> = branches.iter().collect();
    run(&client, "merge of 16", &merge, &refs, &fee);
}
