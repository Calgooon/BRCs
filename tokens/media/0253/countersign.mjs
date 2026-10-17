import { PrivateKey, Transaction, Script, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash, OP } from '@bsv/sdk'

const holder = PrivateKey.fromRandom(), recipient = PrivateKey.fromRandom()
const issuerA = PrivateKey.fromRandom(), issuerB = PrivateKey.fromRandom(), feeKey = PrivateKey.fromRandom()
const tokenId = Array.from(Hash.sha256([1,2,3]))               // 32-byte deploy txid
const num = (n) => { const s = new Script(); s.writeNumber(n); return s.chunks[0] }

/** BRC-162 prefix + countersign clause, m-of-n issuer keys. */
function clause(pkh, amount, m, keys) {
  const s = new Script()
  s.writeBin(tokenId); s.chunks.push(num(amount)); s.writeOpCode(OP.OP_2DROP)
  s.writeOpCode(OP.OP_DUP).writeOpCode(OP.OP_HASH160).writeBin(pkh).writeOpCode(OP.OP_EQUALVERIFY).writeOpCode(OP.OP_CHECKSIGVERIFY)
  s.writeOpCode(OP.OP_1 + m - 1); for (const k of keys) s.writeBin(k.toPublicKey().encode(true)); s.writeOpCode(OP.OP_1 + keys.length - 1)
  s.writeOpCode(OP.OP_CHECKMULTISIG)
  return LockingScript.fromBinary(s.toBinary())
}
const keys = [issuerA, issuerB]                                // 1-of-2: either issuer service may countersign
const pkh = (k) => k.toPublicKey().toHash()
const parentLock = clause(pkh(holder), 100, 1, keys)
const parent = new Transaction(); parent.addOutput({ lockingScript: parentLock, satoshis: 1 })
const feeParent = new Transaction(); feeParent.addOutput({ lockingScript: new Script().writeOpCode(OP.OP_TRUE), satoshis: 200 })

function sig(tx, i, key, scope) {
  const inp = tx.inputs[i]
  const pre = TransactionSignature.format({ sourceTXID: inp.sourceTXID, sourceOutputIndex: inp.sourceOutputIndex,
    sourceSatoshis: inp.sourceTransaction.outputs[inp.sourceOutputIndex].satoshis, transactionVersion: tx.version,
    otherInputs: tx.inputs.filter((_, j) => j !== i), inputIndex: i, outputs: tx.outputs, inputSequence: inp.sequence,
    subscript: inp.sourceTransaction.outputs[inp.sourceOutputIndex].lockingScript, lockTime: tx.lockTime, scope })
  const s = key.sign(Hash.sha256(pre)); return new TransactionSignature(s.r, s.s, scope).toChecksigFormat()
}
const ALL = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID
const ACP = ALL | TransactionSignature.SIGHASH_ANYONECANPAY

// 1. Sender: token input only, recipient + change, holder signs ALL|ANYONECANPAY.
const tx = new Transaction()
tx.addInput({ sourceTransaction: parent, sourceTXID: parent.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
tx.addOutput({ lockingScript: clause(pkh(recipient), 60, 1, keys), satoshis: 1 })
tx.addOutput({ lockingScript: clause(pkh(holder), 40, 1, keys), satoshis: 1 })
const holderSig = sig(tx, 0, holder, ACP)

// 2. Issuer: adds its fee input AFTER the holder signed, then countersigns ALL.
tx.addInput({ sourceTransaction: feeParent, sourceTXID: feeParent.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
const issuerSig = sig(tx, 0, issuerB, ALL)
const unlock = (iss, h) => { const s = new Script(); s.writeOpCode(OP.OP_0); for (const x of iss) s.writeBin(x); s.writeBin(h); s.writeBin(holder.toPublicKey().encode(true)); return UnlockingScript.fromBinary(s.toBinary()) }
tx.inputs[0].unlockingScript = unlock([issuerSig], holderSig)

// 3. Recipient: only the EF bytes.
const ef = tx.toEF()
const got = Transaction.fromEF(ef)
function verify(t, i, lockOverride, satsOverride) {
  const inp = t.inputs[i], src = inp.sourceTransaction.outputs[inp.sourceOutputIndex]
  return new Spend({ sourceTXID: inp.sourceTXID, sourceOutputIndex: inp.sourceOutputIndex, sourceSatoshis: satsOverride ?? src.satoshis,
    lockingScript: lockOverride ?? src.lockingScript, transactionVersion: t.version, otherInputs: t.inputs.filter((_, j) => j !== i),
    outputs: t.outputs, inputIndex: i, unlockingScript: inp.unlockingScript, inputSequence: inp.sequence, lockTime: t.lockTime }).validate()
}
let failed = 0
const report = (pass, name) => { if (!pass) failed++; console.log((pass ? 'ok   ' : 'FAIL ') + name) }
const ok = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r === true, name) }
const fails = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r !== true, name) }
process.on('exit', () => { if (failed) process.exitCode = 1 })
console.log('EF bytes:', ef.length)
ok('recipient verifies the countersigned input from EF alone', () => verify(got, 0))
fails('a claimed spent output with a bigger amount fails', () => verify(got, 0, clause(pkh(holder), 1000, 1, keys)))
fails('a claimed spent output naming other issuer keys fails', () => verify(got, 0, clause(pkh(holder), 100, 1, [PrivateKey.fromRandom()])))
fails('a claimed spent output with other satoshis fails', () => verify(got, 0, undefined, 2))
fails('holder signature alone does not spend', () => { const t = Transaction.fromEF(ef); t.inputs[0].unlockingScript = unlock([holderSig], holderSig); return verify(t, 0) })
fails('a non-issuer countersignature does not spend', () => { const t = Transaction.fromEF(ef); t.inputs[0].unlockingScript = unlock([sig(t, 0, PrivateKey.fromRandom(), ALL)], holderSig); return verify(t, 0) })
fails('changing an output after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.outputs[0].lockingScript = clause(pkh(PrivateKey.fromRandom()), 60, 1, keys); return verify(t, 0) })
fails('adding another input after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.addInput({ sourceTransaction: feeParent, sourceTXID: feeParent.id('hex'), sourceOutputIndex: 0, sequence: 1, unlockingScript: new UnlockingScript() }); return verify(t, 0) })
