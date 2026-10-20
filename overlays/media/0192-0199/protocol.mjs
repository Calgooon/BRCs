// Corpus utilities. This is not an SDK or a production protocol implementation.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { PublicKey } from "@bsv/sdk";
export const sha = (b) => createHash("sha256").update(b).digest();
export const hash256 = (b) => sha(sha(b));
export const hex = (b) => Buffer.from(b).toString("hex");
export const b64 = (b) => Buffer.from(b).toString("base64");
export function bytes(s) {
  assert.equal(typeof s, "string");
  assert(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),
    "base64",
  );
  const b = Buffer.from(s, "base64");
  assert.equal(b64(b), s, "base64-pad-bits");
  return b;
}
export function identity(s) {
  assert(/^(02|03)[0-9a-f]{64}$/.test(s), "identity-encoding");
  assert(
    BigInt("0x" + s.slice(2)) <
      0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    "identity-field-range",
  );
  const p = PublicKey.fromString(s);
  assert(p.validate() && p.toString() === s, "identity-point");
  return s;
}
export function u64(s) {
  assert(
    typeof s === "string" &&
      /^(0|[1-9][0-9]*)$/.test(s) &&
      BigInt(s) <= 18446744073709551615n,
    "u64",
  );
  return BigInt(s);
}
export function canonical(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") {
    assert(v.isWellFormed(), "surrogate");
    return JSON.stringify(v);
  }
  if (typeof v === "number") {
    assert(Number.isSafeInteger(v), "safe-integer");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  assert(v && typeof v === "object" && !Buffer.isBuffer(v), "json-type");
  return (
    "{" +
    Object.keys(v)
      .sort()
      .map((k) => canonical(k) + ":" + canonical(v[k]))
      .join(",") +
    "}"
  );
}
// A bounded JSON parser preserving duplicate decoded keys before object creation.
export function parseJSON(input) {
  const data = typeof input === "string" ? Buffer.from(input) : input;
  assert(data.length <= 4194304, "body-limit");
  const s = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
    data,
  );
  assert(s.charCodeAt(0) !== 0xfeff, "bom");
  let i = 0;
  const ws = () => {
    while (/[ \r\n\t]/.test(s[i] ?? "\0")) i++;
  };
  function string() {
    const start = i++;
    let escaped = false;
    for (; i < s.length; i++) {
      if (!escaped && s[i] === '"') {
        const value = JSON.parse(s.slice(start, ++i));
        assert(value.isWellFormed(), "surrogate");
        return value;
      }
      if (!escaped && s[i] === "\\") escaped = true;
      else escaped = false;
    }
    throw Error("unterminated-string");
  }
  function value(depth) {
    assert(depth <= 32, "depth");
    ws();
    const c = s[i];
    if (c === '"') return string();
    if (c === "{") {
      i++;
      ws();
      const o = Object.create(null),
        seen = new Set();
      if (s[i] === "}") {
        i++;
        return o;
      }
      while (true) {
        ws();
        assert.equal(s[i], '"', "key");
        const k = string();
        assert(!seen.has(k), "duplicate-key");
        seen.add(k);
        assert(seen.size <= 256, "map-limit");
        ws();
        assert.equal(s[i++], ":");
        o[k] = value(depth + 1);
        ws();
        const end = s[i++];
        if (end === "}") return o;
        assert.equal(end, ",");
      }
    }
    if (c === "[") {
      i++;
      ws();
      const a = [];
      if (s[i] === "]") {
        i++;
        return a;
      }
      while (true) {
        a.push(value(depth + 1));
        assert(a.length <= 4096, "array-limit");
        ws();
        const end = s[i++];
        if (end === "]") return a;
        assert.equal(end, ",");
      }
    }
    const token =
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
        s.slice(i),
      )?.[0];
    assert(token, "token");
    i += token.length;
    const v = JSON.parse(token);
    if (typeof v === "number") assert(Number.isSafeInteger(v), "safe-integer");
    return v;
  }
  const v = value(1);
  ws();
  assert.equal(i, s.length, "trailing");
  return v;
}
export function closed(v, required, optional = []) {
  assert(v && typeof v === "object" && !Array.isArray(v), "object");
  for (const k of required) assert(Object.hasOwn(v, k), "missing " + k);
  for (const k of Object.keys(v))
    assert([...required, ...optional].includes(k), "unknown " + k);
}
export function extensions(v, supported = []) {
  const e = v.extensions ?? {},
    c = v.critical ?? [];
  assert(
    Object.keys(e).length <= 32 &&
      c.length <= 32 &&
      new Set(c).size === c.length,
    "critical-duplicates",
  );
  for (const k of Object.keys(e))
    assert(/^[a-z][a-z0-9+.-]*:/.test(k), "extension-iri");
  for (const k of c)
    assert(
      Object.hasOwn(e, k) && supported.includes(k),
      "unsupported-critical",
    );
}
export const preimage = (t, b) =>
  Buffer.concat([
    Buffer.from("BRC-OUTPUT/1/" + t + "\0"),
    Buffer.from(canonical(b)),
  ]);
export const digest = (t, b) => hex(sha(preimage(t, b)));
export const equal = (a, b) => canonical(a) === canonical(b);
export function varint(n) {
  n = BigInt(n);
  if (n < 0n) n = (1n << 64n) + n;
  if (n < 253n) return Buffer.from([Number(n)]);
  if (n <= 65535n) {
    const b = Buffer.alloc(3);
    b[0] = 253;
    b.writeUInt16LE(Number(n), 1);
    return b;
  }
  if (n <= 4294967295n) {
    const b = Buffer.alloc(5);
    b[0] = 254;
    b.writeUInt32LE(Number(n), 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = 255;
  b.writeBigUInt64LE(n, 1);
  return b;
}
function head(major, n) {
  n = BigInt(n);
  if (n < 24n) return Buffer.from([major * 32 + Number(n)]);
  for (const [size, tag, max] of [
    [1, 24, 255n],
    [2, 25, 65535n],
    [4, 26, 4294967295n],
    [8, 27, 18446744073709551615n],
  ])
    if (n <= max) {
      const b = Buffer.alloc(size + 1);
      b[0] = major * 32 + tag;
      for (let j = size; j; j--) {
        b[j] = Number(n & 255n);
        n >>= 8n;
      }
      return b;
    }
  throw Error("cbor-uint");
}
export function cbor(v) {
  if (v === false) return Buffer.from([244]);
  if (v === true) return Buffer.from([245]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === "string") {
    assert(v === v.normalize("NFC"), "NFC");
    const b = Buffer.from(v);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof v === "number" || typeof v === "bigint") {
    assert(BigInt(v) >= 0n);
    return head(0, v);
  }
  if (Array.isArray(v))
    return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  const pairs = Object.entries(v)
    .map(([k, x]) => [cbor(k), cbor(x)])
    .sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
export const lchPreimage = (t, b) =>
  Buffer.concat([Buffer.from("LCH/" + t + "/1\0"), cbor(b)]);
export const lchId = (t, b) => sha(lchPreimage(t, b));
export function diagnostic(v) {
  if (Buffer.isBuffer(v)) return { $bytes: hex(v) };
  if (Array.isArray(v)) return v.map(diagnostic);
  if (v && typeof v === "object")
    return Object.fromEntries(
      Object.entries(v).map(([k, x]) => [k, diagnostic(x)]),
    );
  return v;
}
export function undiagnostic(v) {
  if (
    v &&
    typeof v === "object" &&
    Object.keys(v).length === 1 &&
    v.$bytes !== undefined
  )
    return Buffer.from(v.$bytes, "hex");
  if (Array.isArray(v)) return v.map(undiagnostic);
  if (v && typeof v === "object")
    return Object.fromEntries(
      Object.entries(v).map(([k, x]) => [k, undiagnostic(x)]),
    );
  return v;
}
export function httpPayload(t) {
  const parts = [bytes(t.requestId)];
  const sized = (x) => {
    const b = Buffer.from(x);
    return Buffer.concat([varint(b.length), b]);
  };
  if (t.kind === "request")
    parts.push(
      sized(t.method),
      sized(t.path),
      t.query ? sized(t.query) : varint(-1),
    );
  else parts.push(varint(t.status));
  const headers = Object.entries(t.headers)
    .filter(
      ([k]) =>
        k === "authorization" ||
        (t.kind === "request" && k === "content-type") ||
        (k.startsWith("x-bsv-") && !k.startsWith("x-bsv-auth-")),
    )
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  parts.push(varint(headers.length));
  for (const [k, v] of headers) parts.push(sized(k), sized(v));
  const body = bytes(t.body);
  parts.push(varint(body.length), body);
  return Buffer.concat(parts);
}
export function purchaseReceipt(d, acquisitionId, requestDigest, recipient) {
  return Buffer.concat([
    Buffer.from("006a4ca7524f534c0101", "hex"),
    Buffer.from(d.listingId, "hex"),
    Buffer.from(acquisitionId, "hex"),
    Buffer.from(requestDigest, "hex"),
    Buffer.from(recipient, "hex"),
    Buffer.from(d.termsDigest, "hex"),
  ]);
}
