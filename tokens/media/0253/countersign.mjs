// BRC-253 countersign clause and §11 resolution, checked with @bsv/sdk's script interpreter.
// Run: npm install && npm test
import { PrivateKey, PublicKey, KeyDeriver, ProtoWallet, Transaction, Script, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash, BigNumber, OP, Utils } from '@bsv/sdk'

const holder = PrivateKey.fromRandom(), recipient = PrivateKey.fromRandom()
const issuer = [PrivateKey.fromRandom(), PrivateKey.fromRandom()]                          // 1-of-2, hot
const release = [PrivateKey.fromRandom(), PrivateKey.fromRandom(), PrivateKey.fromRandom()] // 2-of-3, custodians
const assetId = (seed) => [...Hash.sha256(Utils.toArray(seed, 'utf8')), 0, 0, 0, 0]          // deploy outpoint: txid ‖ vout LE
const tokenId = assetId('token'), itemId = assetId('item')
const num = (n) => { const s = new Script(); s.writeNumber(n); return s.chunks[0] }
const smallInt = (s, n) => s.writeOpCode(OP.OP_1 + n - 1)
const hex = (b) => Utils.toHex(b)

function multisig(s, m, keys) {
  smallInt(s, m); for (const k of keys) s.writeBin(k.toPublicKey().encode(true)); smallInt(s, keys.length)
  s.writeOpCode(OP.OP_CHECKMULTISIG)
}
/** Countersign clause alone: holder AND (issuer m-of-n OR release k-of-j). */
function clauseOnly(pkh, iss = issuer, suc = release) {
  const s = new Script()
  s.writeOpCode(OP.OP_DUP).writeOpCode(OP.OP_HASH160).writeBin(pkh).writeOpCode(OP.OP_EQUALVERIFY).writeOpCode(OP.OP_CHECKSIGVERIFY)
  s.writeOpCode(OP.OP_IF); multisig(s, 1, iss); s.writeOpCode(OP.OP_ELSE); multisig(s, 2, suc); s.writeOpCode(OP.OP_ENDIF)
  return s
}
/** BRC-162 prefix + countersign clause. An item is the same output with amount 1. */
function clause(pkh, amount, iss = issuer, suc = release, id = tokenId) {
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
/** OP_0 <countersignatures> <branch> <holder sig> <holder pubkey>; branch OP_1 = issuer, OP_0 = release. */
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
/** The branch push sits third from the end: `… <branch> <holder sig> <holder pubkey>`. */
const usesReleaseBranch = (inp) => { const c = inp.unlockingScript.chunks; return c[c.length - 3]?.op === OP.OP_0 }
function resolve(efBytes, deploys, me) {
  const t = Transaction.fromEF(efBytes), ins = {}, outs = {}
  t.inputs.forEach((inp, i) => {
    const a = readAsset(inp.sourceTransaction.outputs[inp.sourceOutputIndex].lockingScript)
    if (!a || !deploys[a.id]) return
    if (!keepsClause(a, deploys[a.id]) || verify(t, i) !== true) throw new Error('input')
    if (usesReleaseBranch(inp) && !deploys[a.id].released) throw new Error('release branch before a release')
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
const deploys = { [hex(tokenId)]: { kind: 'token', iss: issuer, suc: release }, [hex(itemId)]: { kind: 'item', iss: issuer, suc: release } }

// Item transfer: same clause, amount 1.
const itemParent = fundedBy([{ lockingScript: clause(pkh(holder), 1, issuer, release, itemId), satoshis: 1 }])
function itemTransfer(amounts) {
  const t = new Transaction(); t.addInput(spendOf(itemParent))
  for (const a of amounts) t.addOutput({ lockingScript: clause(pkh(recipient), a, issuer, release, itemId), satoshis: 1 })
  const hs = sig(t, 0, holder, ACP); t.addInput(spendOf(feeParent))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', hs)
  return t.toEF()
}
// Same-issuer swap: holder gives the item, recipient gives 25 tokens, one transaction, both sign ACP, issuer countersigns both.
const buyerTokens = fundedBy([{ lockingScript: clause(pkh(recipient), 30), satoshis: 1 }])
function swap(itemTo = recipient) {
  const t = new Transaction()
  t.addInput(spendOf(itemParent)); t.addInput(spendOf(buyerTokens))
  t.addOutput({ lockingScript: clause(pkh(itemTo), 1, issuer, release, itemId), satoshis: 1 })
  t.addOutput({ lockingScript: clause(pkh(holder), 25), satoshis: 1 })
  t.addOutput({ lockingScript: clause(pkh(recipient), 5), satoshis: 1 })
  const a = sig(t, 0, holder, ACP), b = sig(t, 1, recipient, ACP)
  t.addInput(spendOf(feeParent))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', a)
  t.inputs[1].unlockingScript = unlock([sig(t, 1, issuer[0], ALL)], 'issuer', b, recipient)
  return t.toEF()
}
// §6 sender-funded sale: the seller signs its item input SINGLE|ANYONECANPAY bound to its payment at
// the same index, before any buyer exists. A buyer appends its item output and its own coin, then the
// issuer countersigns. The buyer funds and broadcasts; the issuer adds nothing.
const SALE = TransactionSignature.SIGHASH_SINGLE | TransactionSignature.SIGHASH_ANYONECANPAY | TransactionSignature.SIGHASH_FORKID
const payment = () => ({ lockingScript: new Script().writeOpCode(OP.OP_DUP).writeOpCode(OP.OP_HASH160).writeBin(pkh(holder)).writeOpCode(OP.OP_EQUALVERIFY).writeOpCode(OP.OP_CHECKSIG), satoshis: 500 })
const saleSig = (() => { const t = new Transaction(); t.addInput(spendOf(itemParent)); t.addOutput(payment()); return sig(t, 0, holder, SALE) })()
function sale(buyer = recipient, coinSats = 1000) {
  const t = new Transaction()
  t.addInput(spendOf(itemParent)); t.addInput(spendOf(fundedBy([{ lockingScript: new Script().writeOpCode(OP.OP_TRUE), satoshis: coinSats }])))
  t.addOutput(payment())
  t.addOutput({ lockingScript: clause(pkh(buyer), 1, issuer, release, itemId), satoshis: 1 })
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', saleSig)
  return t.toEF()
}
// A forger copies the issuer's key sets into its own deploy and pays the recipient directly.
const forgedDeploy = (() => { const t = new Transaction(); t.addInput(spendOf(feeParent)); t.addOutput({ lockingScript: clause(pkh(recipient), 1, issuer, release, itemId), satoshis: 1 }); return t.toEF() })()

let failed = 0
const report = (pass, name) => { if (!pass) failed++; console.log((pass ? 'ok   ' : 'FAIL ') + name) }
const ok = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r === true, name) }
const fails = (name, f) => { let r; try { r = f() } catch { r = false } ; report(r !== true, name) }

console.log(`EF bytes: ${ef.length}`)
ok('recipient verifies the issuer-countersigned input from EF alone', () => verify(Transaction.fromEF(ef)))
fails('a claimed spent output with a bigger amount fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 1000)))
fails('a claimed spent output naming other issuer keys fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 100, [PrivateKey.fromRandom()])))
fails('a claimed spent output naming other release keys fails', () => verify(Transaction.fromEF(ef), 0, clause(pkh(holder), 100, issuer, [PrivateKey.fromRandom(), PrivateKey.fromRandom()])))
fails('a claimed spent output with other satoshis fails', () => verify(Transaction.fromEF(ef), 0, undefined, 2))
fails('holder signature alone does not spend', () => verify(withUnlock(() => unlock([holderSig], 'issuer', holderSig))))
fails('a key outside the set does not countersign', () => verify(withUnlock((t) => unlock([sig(t, 0, PrivateKey.fromRandom(), ALL)], 'issuer', holderSig))))
fails('changing an output after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.outputs[0].lockingScript = clause(pkh(PrivateKey.fromRandom()), 60); return verify(t) })
fails('adding an input after the issuer signed fails', () => { const t = Transaction.fromEF(ef); t.addInput(spendOf(feeParent)); return verify(t) })
ok('two release keys countersign through the release branch', () => verify(withUnlock((t) => unlock([sig(t, 0, release[0], ALL), sig(t, 0, release[2], ALL)], 'release', holderSig))))
fails('one release key is not enough', () => verify(withUnlock((t) => unlock([sig(t, 0, release[1], ALL)], 'release', holderSig))))
fails('release keys cannot use the issuer branch', () => verify(withUnlock((t) => unlock([sig(t, 0, release[0], ALL)], 'issuer', holderSig))))
fails('an issuer key cannot use the release branch', () => verify(withUnlock((t) => unlock([sig(t, 0, issuer[0], ALL), sig(t, 0, release[0], ALL)], 'release', holderSig))))
fails('release keys cannot spend without the holder', () => verify(withUnlock((t) => unlock([sig(t, 0, release[0], ALL), sig(t, 0, release[1], ALL)], 'release', sig(t, 0, PrivateKey.fromRandom(), ACP)))))
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
  const t = Transaction.fromEF(swap()); t.outputs[0].lockingScript = clause(pkh(PrivateKey.fromRandom()), 1, issuer, release, itemId); return verify(t, 0)
})
ok('a sale signed before the buyer existed verifies once a buyer completes it and the issuer countersigns', () => verify(Transaction.fromEF(sale())))
ok('the sale resolves the item to the buyer', () => { const m = resolve(sale(), deploys, recipient); return m.length === 1 && m[0].id === hex(itemId) })
ok('two buyers can each complete the same signed sale; both spend the item, so at most one is mined', () => {
  const a = Transaction.fromEF(sale(recipient)), b = Transaction.fromEF(sale(PrivateKey.fromRandom(), 2000))
  return verify(a) && verify(b) && a.id('hex') !== b.id('hex')
})
fails('lowering the seller payment after the seller signed fails', () => {
  const t = Transaction.fromEF(sale()); t.outputs[0].satoshis = 1; t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', saleSig); return verify(t)
})

// §6 replacement: same token input, byte-identical outputs, a different acceptor fee input. The holder's
// ALL|ANYONECANPAY signature covers only its own input and the outputs, so it is reused unchanged.
const feeParent2 = fundedBy([{ lockingScript: new Script().writeOpCode(OP.OP_TRUE), satoshis: 300 }])
const replacement = (() => {
  const t = new Transaction(); t.addInput(spendOf(parent))
  for (const o of tx.outputs) t.addOutput({ lockingScript: o.lockingScript, satoshis: o.satoshis })
  t.addInput(spendOf(feeParent2))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', holderSig)
  return t
})()
ok('a replacement with a new acceptor fee input verifies with the original holder signature', () => verify(replacement))
ok('the replacement has a new txid and byte-identical outputs', () =>
  replacement.id('hex') !== tx.id('hex') && hex(replacement.outputs.flatMap((o) => o.lockingScript.toBinary())) === hex(tx.outputs.flatMap((o) => o.lockingScript.toBinary())))
fails('a replacement that changes an output does not verify with the original holder signature', () => {
  const t = Transaction.fromEF(replacement.toEF()); t.outputs[1].lockingScript = clause(pkh(PrivateKey.fromRandom()), 40)
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', holderSig); return verify(t)
})

// §11 release branch: custodians can countersign a live asset's transfer without publishing a release.
const custodianTransfer = withUnlock((t) => unlock([sig(t, 0, release[0], ALL), sig(t, 0, release[1], ALL)], 'release', holderSig)).toEF()
ok('custodians can countersign a live asset privately: script validation passes', () => verify(Transaction.fromEF(custodianTransfer)))
fails('resolution refuses a release-branch input while no release is known', () => resolve(custodianTransfer, deploys, recipient).length > 0)
ok('resolution accepts the same input once the release is known', () => {
  const released = { ...deploys, [hex(tokenId)]: { ...deploys[hex(tokenId)], released: true } }
  return resolve(custodianTransfer, released, recipient).length === 1
})

// §9 beacon: OP_IF <issuer m-of-n> OP_ELSE <release k-of-j> OP_ENDIF.
function beaconLock() {
  const s = new Script(); s.writeOpCode(OP.OP_IF); multisig(s, 1, issuer); s.writeOpCode(OP.OP_ELSE); multisig(s, 2, release); s.writeOpCode(OP.OP_ENDIF)
  return LockingScript.fromBinary(s.toBinary())
}
const beaconUnlock = (sigs, branch) => { const s = new Script(); s.writeOpCode(OP.OP_0); for (const x of sigs) s.writeBin(x); s.writeOpCode(branch === 'issuer' ? OP.OP_1 : OP.OP_0); return UnlockingScript.fromBinary(s.toBinary()) }
const beacon = fundedBy([{ lockingScript: beaconLock(), satoshis: 1 }])
const RELEASE_TAG = Utils.toArray('countersign release', 'utf8')
function beaconSpend(outputs, sign) {
  const t = new Transaction(); t.addInput(spendOf(beacon)); t.addInput(spendOf(feeParent))
  for (const o of outputs) t.addOutput(o)
  t.inputs[0].unlockingScript = sign(t); return t
}
const refresh = () => beaconSpend([{ lockingScript: beaconLock(), satoshis: 1 }], (t) => beaconUnlock([sig(t, 0, issuer[0], ALL)], 'issuer'))
function disclosure(keys, id = tokenId) {
  const s = new Script(); s.writeOpCode(OP.OP_FALSE).writeOpCode(OP.OP_RETURN).writeBin(RELEASE_TAG).writeBin(id)
  for (const k of keys) s.writeBin(k.toArray('be', 32))
  return LockingScript.fromBinary(s.toBinary())
}
const releaseTx = (keys = [release[0], release[2]]) => beaconSpend([{ lockingScript: disclosure(keys), satoshis: 0 }],
  (t) => beaconUnlock([sig(t, 0, release[0], ALL), sig(t, 0, release[2], ALL)], 'release'))
// A wallet reads a release from the beacon spend alone: k distinct disclosed keys of the release set.
function readRelease(t, id = tokenId) {
  const pushes = (o) => { const c = o.lockingScript.chunks; return c[0]?.op === OP.OP_FALSE && c[1]?.op === OP.OP_RETURN && c[1].data ? Script.fromBinary(c[1].data).chunks : [] }
  const c = t.outputs.map(pushes).find((p) => p[0]?.data && hex(p[0].data) === hex(RELEASE_TAG))
  if (!c || hex(c[1]?.data ?? []) !== hex(id)) return null
  const pubs = release.map((k) => hex(k.toPublicKey().encode(true)))
  const keys = c.slice(2).map((x) => new PrivateKey(x.data))
  const named = new Set(keys.map((k) => hex(k.toPublicKey().encode(true))).filter((p) => pubs.includes(p)))
  return named.size >= 2 && named.size === keys.length ? keys : null
}

ok('the issuer refreshes its beacon through the issuer branch', () => verify(refresh()))
fails('release keys cannot refresh the beacon through the issuer branch', () => verify(beaconSpend([{ lockingScript: beaconLock(), satoshis: 1 }], (t) => beaconUnlock([sig(t, 0, release[0], ALL)], 'issuer'))))
fails('an issuer key cannot release through the release branch', () => verify(beaconSpend([{ lockingScript: disclosure([release[0], release[1]]), satoshis: 0 }], (t) => beaconUnlock([sig(t, 0, issuer[0], ALL), sig(t, 0, release[1], ALL)], 'release'))))
ok('two release keys spend the final beacon and disclose their private keys', () => verify(releaseTx()) && readRelease(releaseTx()) !== null)
fails('a disclosure with one key, or a key outside the set, is no release', () => readRelease(releaseTx([release[0]])) !== null || readRelease(releaseTx([release[0], PrivateKey.fromRandom()])) !== null)
ok('after release anyone countersigns with the disclosed keys; the holder still signs', () => {
  const keys = readRelease(releaseTx())
  return verify(withUnlock((t) => unlock([sig(t, 0, keys[0], ALL), sig(t, 0, keys[1], ALL)], 'release', holderSig)))
})
fails('after release a stranger still cannot spend without the holder', () => {
  const keys = readRelease(releaseTx())
  return verify(withUnlock((t) => unlock([sig(t, 0, keys[0], ALL), sig(t, 0, keys[1], ALL)], 'release', sig(t, 0, PrivateKey.fromRandom(), ACP))))
})

// §2 holder keys and §5 linkage: the sender derives the recipient's BRC-29 child; the acceptor opens the
// specific linkage sealed to it and checks identityKey + linkage·G against the holder pubkey hash.
const brc29Proto = [2, '3241645161d8']
const brc29KeyID = 'cHJlZml4 c3VmZml4'
const pubOf = (k) => k.toPublicKey().toString()
const childPub = new KeyDeriver(holder).derivePublicKey(brc29Proto, brc29KeyID, pubOf(recipient))
const childPriv = new KeyDeriver(recipient).derivePrivateKey(brc29Proto, brc29KeyID, pubOf(holder))
const revealed = await new ProtoWallet(holder).revealSpecificKeyLinkage({
  counterparty: pubOf(recipient), verifier: pubOf(issuer[0]), protocolID: brc29Proto, keyID: brc29KeyID,
})
const opened = (acceptorKey) => {
  const sym = new KeyDeriver(acceptorKey).deriveSymmetricKey([2, `specific linkage revelation 2 ${brc29Proto[1]}`], brc29KeyID, pubOf(holder))
  const linkage = sym.decrypt(revealed.encryptedLinkage)
  return hex(new PublicKey(recipient.toPublicKey().add(new PrivateKey(linkage).toPublicKey())).toHash())
}
ok('the recipient derives the private key of the holder hash its sender wrote', () => hex(childPriv.toPublicKey().toHash()) === hex(childPub.toHash()))
fails('the holder hash is not the recipient identity hash', () => hex(childPub.toHash()) === hex(pkh(recipient)))
ok('the acceptor opens the linkage sealed to it, and it hashes to the holder hash', () => opened(issuer[0]) === hex(childPub.toHash()))
fails('no other acceptor key opens that linkage', () => opened(issuer[1]) === hex(childPub.toHash()))
ok('the derived holder key spends under the issuer countersignature', () => {
  const held = fundedBy([{ lockingScript: clause(childPub.toHash(), 5), satoshis: 1 }])
  const t = new Transaction()
  t.addInput(spendOf(held))
  t.addOutput({ lockingScript: clause(pkh(holder), 5), satoshis: 1 })
  const hs = sig(t, 0, childPriv, ACP)
  t.addInput(spendOf(feeParent))
  t.inputs[0].unlockingScript = unlock([sig(t, 0, issuer[0], ALL)], 'issuer', hs, childPriv)
  return verify(t)
})
if (failed) process.exitCode = 1
