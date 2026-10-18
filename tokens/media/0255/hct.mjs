// BRC-255 test script: §1 clauses under the @bsv/sdk interpreter, §3 issuer key derivation.
import { Hash, LockingScript, OP, P2PKH, PrivateKey, Spend, Transaction, TransactionSignature, UnlockingScript } from '@bsv/sdk'

const MARKER = [0x68, 0x63, 0x74]
const HOLDER_SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_ANYONECANPAY | TransactionSignature.SIGHASH_FORKID
const ISSUER_SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID

const holder = PrivateKey.fromRandom()
const issuer = PrivateKey.fromRandom()
const secret = Array.from(PrivateKey.fromRandom().toArray('be', 32))
const rel = Hash.hash160(secret)
const assetId = Hash.hash160([...new Array(32).fill(1), 0])

const prefix = (amount) => new LockingScript().writeBin([...MARKER, ...assetId]).writeBin(amount).writeOpCode(OP.OP_2DROP)

const countersigned = prefix([0x40, 0x42, 0x0f])
  .writeBin(holder.toPublicKey().encode(true)).writeOpCode(OP.OP_CHECKSIGVERIFY).writeOpCode(OP.OP_IF)
  .writeBin(issuer.toPublicKey().encode(true)).writeOpCode(OP.OP_CHECKSIG)
  .writeOpCode(OP.OP_ELSE).writeOpCode(OP.OP_HASH160).writeBin(rel).writeOpCode(OP.OP_EQUAL).writeOpCode(OP.OP_ENDIF)
const open = prefix([0x40, 0x42, 0x0f]).writeBin(holder.toPublicKey().encode(true)).writeOpCode(OP.OP_CHECKSIG)

function verifies(lock, unlock) {
  const parent = new Transaction()
  parent.addInput({ sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff })
  parent.addOutput({ satoshis: 1, lockingScript: lock })
  const tx = new Transaction()
  tx.addInput({ sourceTransaction: parent, sourceOutputIndex: 0, sequence: 0xffffffff })
  tx.addOutput({ satoshis: 1, lockingScript: new P2PKH().lock(holder.toAddress()) })
  const common = {
    sourceTXID: parent.id('hex'), sourceOutputIndex: 0, sourceSatoshis: 1, transactionVersion: tx.version,
    otherInputs: [], inputIndex: 0, outputs: tx.outputs, inputSequence: 0xffffffff, lockTime: tx.lockTime,
  }
  const sign = (key, scope) => {
    const s = key.sign(Hash.sha256(TransactionSignature.format({ ...common, subscript: lock, scope })))
    return new TransactionSignature(s.r, s.s, scope).toChecksigFormat()
  }
  try {
    return new Spend({ ...common, lockingScript: lock, unlockingScript: unlock(sign) }).validate()
  } catch {
    return false
  }
}

const u = () => new UnlockingScript()
const checks = [
  ['countersigned: issuer branch', true, verifies(countersigned, (s) => u().writeBin(s(issuer, ISSUER_SCOPE)).writeOpCode(OP.OP_1).writeBin(s(holder, HOLDER_SCOPE)))],
  ['countersigned: release branch with the secret', true, verifies(countersigned, (s) => u().writeBin(secret).writeOpCode(OP.OP_0).writeBin(s(holder, HOLDER_SCOPE)))],
  ['countersigned: holder without issuer', false, verifies(countersigned, (s) => u().writeOpCode(OP.OP_0).writeOpCode(OP.OP_1).writeBin(s(holder, HOLDER_SCOPE)))],
  ['countersigned: wrong secret', false, verifies(countersigned, (s) => u().writeBin(new Array(32).fill(9)).writeOpCode(OP.OP_0).writeBin(s(holder, HOLDER_SCOPE)))],
  ['countersigned: secret without holder', false, verifies(countersigned, (s) => u().writeBin(secret).writeOpCode(OP.OP_0).writeBin(s(issuer, HOLDER_SCOPE)))],
  ['countersigned: issuer in the holder slot', false, verifies(countersigned, (s) => u().writeBin(s(issuer, ISSUER_SCOPE)).writeOpCode(OP.OP_1).writeBin(s(issuer, HOLDER_SCOPE)))],
  ['open: holder', true, verifies(open, (s) => u().writeBin(s(holder, HOLDER_SCOPE)))],
  ['open: stranger', false, verifies(open, (s) => u().writeBin(s(issuer, HOLDER_SCOPE)))],
]

const identity = PrivateKey.fromRandom()
const anyone = new PrivateKey(1)
const byIssuer = identity.deriveChild(anyone.toPublicKey(), '2-hct issuer-1').toPublicKey().toString()
const byReader = identity.toPublicKey().deriveChild(anyone, '2-hct issuer-1').toString()
checks.push(['§3 issuer key derivable from iss', true, byIssuer === byReader])
checks.push(['§1 held prefix push is 23 bytes', true, countersigned.chunks[0].data.length === 23])

let failed = 0
for (const [name, want, got] of checks) {
  const ok = want === got
  if (!ok) failed += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`)
}
console.log(`lock bytes: countersigned ${countersigned.toBinary().length}, open ${open.toBinary().length}`)
process.exit(failed ? 1 : 0)
