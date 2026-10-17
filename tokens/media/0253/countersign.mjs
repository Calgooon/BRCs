// BRC-253 countersign clause, checked with @bsv/sdk's script interpreter.
// Run: npm install && npm test
import { PrivateKey, Transaction, Script, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash, OP } from '@bsv/sdk'

const holder = PrivateKey.fromRandom(), recipient = PrivateKey.fromRandom()
const issuer = [PrivateKey.fromRandom(), PrivateKey.fromRandom()]                          // 1-of-2, hot
const successor = [PrivateKey.fromRandom(), PrivateKey.fromRandom(), PrivateKey.fromRandom()] // 2-of-3, cold
const tokenId = Array.from(Hash.sha256([1, 2, 3]))
const num = (n) => { const s = new Script(); s.writeNumber(n); return s.chunks[0] }
const smallInt = (s, n) => s.writeOpCode(OP.OP_1 + n - 1)

function multisig(s, m, keys) {
  smallInt(s, m); for (const k of keys) s.writeBin(k.toPublicKey().encode(true)); smallInt(s, keys.length)
  s.writeOpCode(OP.OP_CHECKMULTISIG)
}
/** BRC-162 prefix + countersign clause: holder AND (issuer m-of-n OR successor k-of-j). */
function clause(pkh, amount, iss = issuer, suc = successor) {
  const s = new Script()
  s.writeBin(tokenId); s.chunks.push(num(amount)); s.writeOpCode(OP.OP_2DROP)
  s.writeOpCode(OP.OP_DUP).writeOpCode(OP.OP_HASH160).writeBin(pkh).writeOpCode(OP.OP_EQUALVERIFY).writeOpCode(OP.OP_CHECKSIGVERIFY)
  s.writeOpCode(OP.OP_IF); multisig(s, 1, iss); s.writeOpCode(OP.OP_ELSE); multisig(s, 2, suc); s.writeOpCode(OP.OP_ENDIF)
  return LockingScript.fromBinary(s.toBinary())
}
const pkh = (k) => k.toPublicKey().toHash()
const parent = new Transaction(); parent.addOutput({ lockingScript: clause(pkh(holder), 100), satoshis: 1 })
const feeParent = new Transaction(); feeParent.addOutput({ lockingScript: new Script().writeOpCode(OP.OP_TRUE), satoshis: 200 })

const ALL = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID
const ACP = ALL | TransactionSignature.SIGHASH_ANYONECANPAY
function sig(tx, i, key, scope) {
  const inp = tx.inputs[i], src = inp.sourceTransaction.outputs[inp.sourceOutputIndex]
  const pre = TransactionSignature.format({ sourceTXID: inp.sourceTXID, sourceOutputIndex: inp.sourceOutputIndex,
    sourceSatoshis: src.satoshis, transactionVersion: tx.version, otherInputs: tx.inputs.filter((_, j) => j !== i),
    inputIndex: i, outputs: tx.outputs, inputSequence: inp.sequence, subscript: src.lockingScript, lockTime: tx.lockTime, scope })
  const s = key.sign(Hash.sha256(pre)); return new TransactionSignature(s.r, s.s, scope).toChecksigFormat()
}
/** OP_0 <countersignatures> <branch> <holder sig> <holder pubkey>; branch OP_1 = issuer, OP_0 = successor. */
function unlock(countersigs, branch, holderSig) {
  const s = new Script(); s.writeOpCode(OP.OP_0); for (const x of countersigs) s.writeBin(x)
  s.writeOpCode(branch === 'issuer' ? OP.OP_1 : OP.OP_0); s.writeBin(holderSig); s.writeBin(holder.toPublicKey().encode(true))
  return UnlockingScript.fromBinary(s.toBinary())
}

// Sender: token input only, recipient + change; holder signs ALL|ANYONECANPAY.
const tx = new Transaction()
tx.addInput({ sourceTransaction: parent, sourceTXID: parent.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
tx.addOutput({ lockingScript: clause(pkh(recipient), 60), satoshis: 1 })
tx.addOutput({ lockingScript: clause(pkh(holder), 40), satoshis: 1 })
const holderSig = sig(tx, 0, holder, ACP)
// Issuer: adds its fee input after the holder signed, then countersigns ALL.
tx.addInput({ sourceTransaction: feeParent, sourceTXID: feeParent.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
tx.inputs[0].unlockingScript = unlock([sig(tx, 0, issuer[1], ALL)], 'issuer', holderSig)
const ef = tx.toEF()

function verify(t, i = 0, lockOverride, satsOverride) {
  const inp = t.inputs[i], src = inp.sourceTransaction.outputs[inp.sourceOutputIndex]
  return new Spend({ sourceTXID: inp.sourceTXID, sourceOutputIndex: inp.sourceOutputIndex, sourceSatoshis: satsOverride ?? src.satoshis,
    lockingScript: lockOverride ?? src.lockingScript, transactionVersion: t.version, otherInputs: t.inputs.filter((_, j) => j !== i),
    outputs: t.outputs, inputIndex: i, unlockingScript: inp.unlockingScript, inputSequence: inp.sequence, lockTime: t.lockTime }).validate()
}
const withUnlock = (make) => { const t = Transaction.fromEF(ef); t.inputs[0].unlockingScript = make(t); return t }

let failed = 0
const report = (pass, name) => { if (!pass) failed++; console.log((pass ? 'ok   ' : 'FAIL ') + name) }
const ok = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r === true, name) }
const fails = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r !== true, name) }

console.log(`EF bytes: ${ef.length}`)
ok('recipient verifies the issuer-countersigned input from EF alone', () => verify(Transaction.fromEF(ef)))
fails('a claimed spent output with a bigger amount fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 1000)))
fails('a claimed spent output naming other issuer keys fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 100, [PrivateKey.fromRandom()])))
fails('a claimed spent output naming other successor keys fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 100, issuer, [PrivateKey.fromRandom(), PrivateKey.fromRandom()])))
fails('a claimed spent output with other satoshis fails', () => verify(Transaction.fromEF(ef), 0, undefined, 2))
fails('holder signature alone does not spend', () => verify(withUnlock(() => unlock([holderSig], 'issuer', holderSig))))
fails('a key outside the set does not countersign', () => verify(withUnlock((t) => unlock([sig(t, 0, PrivateKey.fromRandom(), ALL)], 'issuer', holderSig))))
fails('changing an output after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.outputs[0].lockingScript = clause(pkh(PrivateKey.fromRandom()), 60); return verify(t) })
fails('adding an input after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.addInput({ sourceTransaction: feeParent, sourceTXID: feeParent.id('hex'), sourceOutputIndex: 0, sequence: 1, unlockingScript: new UnlockingScript() }); return verify(t) })
ok('two successor keys countersign through the successor branch', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL), sig(t, 0, successor[2], ALL)], 'successor', holderSig))))
fails('one successor key is not enough', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[1], ALL)], 'successor', holderSig))))
fails('successor keys cannot use the issuer branch', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL)], 'issuer', holderSig))))
fails('an issuer key cannot use the successor branch', () => verify(withUnlock((t) => unlock([sig(t, 0, issuer[0], ALL), sig(t, 0, successor[0], ALL)], 'successor', holderSig))))
fails('successors cannot spend without the holder', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL), sig(t, 0, successor[1], ALL)], 'successor', sig(t, 0, PrivateKey.fromRandom(), ACP)))))
if (failed) process.exitCode = 1
