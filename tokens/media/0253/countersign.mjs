// BRC-253 countersign clause and §11 resolution, checked with @bsv/sdk's script interpreter.
// Run: npm install && npm test
import { PrivateKey, Transaction, Script, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash, BigNumber, OP, Utils } from '@bsv/sdk'

const holder = PrivateKey.fromRandom(), recipient = PrivateKey.fromRandom()
const issuer = [PrivateKey.fromRandom(), PrivateKey.fromRandom()]                          // 1-of-2, hot
const successor = [PrivateKey.fromRandom(), PrivateKey.fromRandom(), PrivateKey.fromRandom()] // 2-of-3, cold
const assetId = (seed) => [...Hash.sha256(Utils.toArray(seed, 'utf8')), 0, 0, 0, 0]          // deploy outpoint: txid ‖ vout LE
const tokenId = assetId('token'), itemId = assetId('item')
const num = (n) => { const s = new Script(); s.writeNumber(n); return s.chunks[0] }
const smallInt = (s, n) => s.writeOpCode(OP.OP_1 + n - 1)
const hex = (b) => Utils.toHex(b)

function multisig(s, m, keys) {
  smallInt(s, m); for (const k of keys) s.writeBin(k.toPublicKey().encode(true)); smallInt(s, keys.length)
  s.writeOpCode(OP.OP_CHECKMULTISIG)
}
/** Countersign clause alone: holder AND (issuer m-of-n OR successor k-of-j). */
function clauseOnly(pkh, iss = issuer, suc = successor) {
  const s = new Script()
  s.writeOpCode(OP.OP_DUP).writeOpCode(OP.OP_HASH160).writeBin(pkh).writeOpCode(OP.OP_EQUALVERIFY).writeOpCode(OP.OP_CHECKSIGVERIFY)
  s.writeOpCode(OP.OP_IF); multisig(s, 1, iss); s.writeOpCode(OP.OP_ELSE); multisig(s, 2, suc); s.writeOpCode(OP.OP_ENDIF)
  return s
}
/** BRC-162 prefix + countersign clause. An item is the same output with amount 1. */
function clause(pkh, amount, iss = issuer, suc = successor, id = tokenId) {
  const s = new Script()
  s.writeBin(id); s.chunks.push(num(amount)); s.writeOpCode(OP.OP_2DROP)
  s.chunks.push(...clauseOnly(pkh, iss, suc).chunks)
  return LockingScript.fromBinary(s.toBinary())
}
const pkh = (k) => k.toPublicKey().toHash()
const fundedBy = (outputs) => { const t = new Transaction(); for (const o of outputs) t.addOutput(o); return t }
const parent = fundedBy([{ lockingScript: clause(pkh(holder), 100), satoshis: 1 }])
const feeParent = fundedBy([{ lockingScript: new Script().writeOpCode(OP.OP_TRUE), satoshis: 200 }])

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
function unlock(countersigs, branch, holderSig, holderKey = holder) {
  const s = new Script(); s.writeOpCode(OP.OP_0); for (const x of countersigs) s.writeBin(x)
  s.writeOpCode(branch === 'issuer' ? OP.OP_1 : OP.OP_0); s.writeBin(holderSig); s.writeBin(holderKey.toPublicKey().encode(true))
  return UnlockingScript.fromBinary(s.toBinary())
}
const spendOf = (src, vout = 0) => ({ sourceTransaction: src, sourceTXID: src.id('hex'), sourceOutputIndex: vout, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })

// Sender: token input only, recipient + change; holder signs ALL|ANYONECANPAY.
const tx = new Transaction()
tx.addInput(spendOf(parent))
tx.addOutput({ lockingScript: clause(pkh(recipient), 60), satoshis: 1 })
tx.addOutput({ lockingScript: clause(pkh(holder), 40), satoshis: 1 })
const holderSig = sig(tx, 0, holder, ACP)
// Issuer: adds its fee input after the holder signed, then countersigns ALL.
tx.addInput(spendOf(feeParent))
tx.inputs[0].unlockingScript = unlock([sig(tx, 0, issuer[1], ALL)], 'issuer', holderSig)
const ef = tx.toEF()

function verify(t, i = 0, lockOverride, satsOverride) {
  const inp = t.inputs[i], src = inp.sourceTransaction.outputs[inp.sourceOutputIndex]
  return new Spend({ sourceTXID: inp.sourceTXID, sourceOutputIndex: inp.sourceOutputIndex, sourceSatoshis: satsOverride ?? src.satoshis,
    lockingScript: lockOverride ?? src.lockingScript, transactionVersion: t.version, otherInputs: t.inputs.filter((_, j) => j !== i),
    outputs: t.outputs, inputIndex: i, unlockingScript: inp.unlockingScript, inputSequence: inp.sequence, lockTime: t.lockTime }).validate()
}
const withUnlock = (make) => { const t = Transaction.fromEF(ef); t.inputs[0].unlockingScript = make(t); return t }

// §11 resolution from one EF transaction. `deploys` maps asset id hex → { kind, iss, suc, authority }.
function readAsset(script) {
  const c = script.chunks
  if (c.length < 4 || c[0].data?.length !== 36 || c[2].op !== OP.OP_2DROP) return null
  const amount = c[1].op >= OP.OP_1 && c[1].op <= OP.OP_16 ? c[1].op - OP.OP_1 + 1 : c[1].data ? BigNumber.fromScriptNum(c[1].data).toNumber() : null
  let rest = 3
  if (c[rest + 1]?.op === OP.OP_DROP && c[rest].data) rest += 2 // optional payload
  const pkhChunk = c[rest + 2]
  return { id: hex(c[0].data), amount, pkh: pkhChunk?.data, clause: new Script(c.slice(rest)).toBinary() }
}
const keepsClause = (a, d) => a.pkh?.length === 20 && hex(a.clause) === hex(clauseOnly(a.pkh, d.iss, d.suc).toBinary())
function resolve(efBytes, deploys, me) {
  const t = Transaction.fromEF(efBytes), ins = {}, outs = {}
  t.inputs.forEach((inp, i) => {
    const a = readAsset(inp.sourceTransaction.outputs[inp.sourceOutputIndex].lockingScript)
    if (!a || !deploys[a.id]) return
    if (!keepsClause(a, deploys[a.id]) || verify(t, i) !== true) throw new Error('input')
    ins[a.id] = (ins[a.id] ?? 0) + a.amount
  })
  const mine = []
  t.outputs.forEach((o, vout) => {
    const a = readAsset(o.lockingScript)
    if (!a || !deploys[a.id]) return
    if (!keepsClause(a, deploys[a.id]) || !(a.amount > 0)) throw new Error('output')
    outs[a.id] = (outs[a.id] ?? 0) + a.amount
    if (hex(a.pkh) === hex(pkh(me))) mine.push({ vout, id: a.id, amount: a.amount })
  })
  for (const id of Object.keys(outs)) {
    if (!(id in ins)) throw new Error('deploy') // a recipient never resolves a deploy; holdings arrive through countersigned spends
    if (outs[id] !== ins[id] && !deploys[id].authority) throw new Error('conservation')
    if (deploys[id].kind === 'item' && outs[id] !== 1) throw new Error('item supply')
  }
  return mine
}
const deploys = { [hex(tokenId)]: { kind: 'token', iss: issuer, suc: successor }, [hex(itemId)]: { kind: 'item', iss: issuer, suc: successor } }

// Item transfer: same clause, amount 1.
const itemParent = fundedBy([{ lockingScript: clause(pkh(holder), 1, issuer, successor, itemId), satoshis: 1 }])
function itemTransfer(amounts) {
  const t = new Transaction(); t.addInput(spendOf(itemParent))
  for (const a of amounts) t.addOutput({ lockingScript: clause(pkh(recipient), a, issuer, successor, itemId), satoshis: 1 })
  const hs = sig(t, 0, holder, ACP); t.addInput(spendOf(feeParent))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', hs)
  return t.toEF()
}
// Same-issuer swap: holder gives the item, recipient gives 25 tokens, one transaction, both sign ACP, issuer countersigns both.
const buyerTokens = fundedBy([{ lockingScript: clause(pkh(recipient), 30), satoshis: 1 }])
function swap(itemTo = recipient) {
  const t = new Transaction()
  t.addInput(spendOf(itemParent)); t.addInput(spendOf(buyerTokens))
  t.addOutput({ lockingScript: clause(pkh(itemTo), 1, issuer, successor, itemId), satoshis: 1 })
  t.addOutput({ lockingScript: clause(pkh(holder), 25), satoshis: 1 })
  t.addOutput({ lockingScript: clause(pkh(recipient), 5), satoshis: 1 })
  const a = sig(t, 0, holder, ACP), b = sig(t, 1, recipient, ACP)
  t.addInput(spendOf(feeParent))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', a)
  t.inputs[1].unlockingScript = unlock([sig(t, 1, issuer[0], ALL)], 'issuer', b, recipient)
  return t.toEF()
}
// A forger copies the issuer's key sets into its own deploy and pays the recipient directly.
const forgedDeploy = (() => { const t = new Transaction(); t.addInput(spendOf(feeParent)); t.addOutput({ lockingScript: clause(pkh(recipient), 1, issuer, successor, itemId), satoshis: 1 }); return t.toEF() })()

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
fails('adding an input after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.addInput(spendOf(feeParent)); return verify(t) })
ok('two successor keys countersign through the successor branch', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL), sig(t, 0, successor[2], ALL)], 'successor', holderSig))))
fails('one successor key is not enough', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[1], ALL)], 'successor', holderSig))))
fails('successor keys cannot use the issuer branch', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL)], 'issuer', holderSig))))
fails('an issuer key cannot use the successor branch', () => verify(withUnlock((t) => unlock([sig(t, 0, issuer[0], ALL), sig(t, 0, successor[0], ALL)], 'successor', holderSig))))
fails('successors cannot spend without the holder', () => verify(withUnlock((t) => unlock([sig(t, 0, successor[0], ALL), sig(t, 0, successor[1], ALL)], 'successor', sig(t, 0, PrivateKey.fromRandom(), ACP)))))
ok('a token transfer resolves to the recipient output', () => { const m = resolve(ef, deploys, recipient); return m.length === 1 && m[0].amount === 60 })
ok('an item transfer resolves to the recipient', () => { const m = resolve(itemTransfer([1]), deploys, recipient); return m.length === 1 && m[0].id === hex(itemId) })
fails('an item written twice is refused', () => resolve(itemTransfer([1, 1]), deploys, recipient).length > 0)
fails('a deploy paid straight to the recipient is refused', () => resolve(forgedDeploy, deploys, recipient).length > 0)
ok('an item-for-tokens swap under one issuer verifies both inputs from EF', () => { const t = Transaction.fromEF(swap()); return verify(t, 0) && verify(t, 1) })
ok('the swap resolves the item to the buyer and 25 tokens to the seller', () => {
  const s = swap(), toBuyer = resolve(s, deploys, recipient), toSeller = resolve(s, deploys, holder)
  return toBuyer.some((o) => o.id === hex(itemId)) && toSeller.length === 1 && toSeller[0].amount === 25
})
fails('changing who receives the item after both signed fails', () => {
  const t = Transaction.fromEF(swap()); t.outputs[0].lockingScript = clause(pkh(PrivateKey.fromRandom()), 1, issuer, successor, itemId); return verify(t, 0)
})
if (failed) process.exitCode = 1
