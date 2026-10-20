# BRC-TBD: Progressive Contraction of Chain-Scanned Address and Transaction Index Spaces

Ty Everett (ty@projectbabbage.com)

## Abstract

This BRC proposes an opt-in, deterministic retirement profile for **general-purpose, publicly queried blockchain address and transaction-ID indexes**. Beginning at BSV block height 1,000,000, participating index services progressively remove records outside smaller and smaller permitted prefix spaces, with advancement gated by both elapsed calendar time and observed non-coinbase transaction volume.

The address-index prefix advances from `1` toward `1ChickenNugget`. Independently, the TXID-index prefix advances from unrestricted to thirteen leading hexadecimal `9` characters. At each stage, records outside the applicable prefix cease to be exposed by the participating legacy index and are retired from that index's storage.

This BRC does **not** restrict valid addresses, locking scripts, transaction IDs, consensus rules, archival blockchain retention, or privately held wallet records. No chain-wide requirement can compel independent index providers to delete data. The proposed requirements apply only to services expressly claiming conformance with this **contracting-index profile**.

## Motivation

Historically, wallets discovered incoming payments by asking services to search blocks, mempools, and historical transactions for outputs matching Bitcoin addresses. Maintaining comprehensive general-purpose lookup indexes is costly at large transaction volumes and encourages applications to depend on blockchain-wide observation rather than receiving relevant transactions directly.

Index growth is driven by the amount of data admitted and retained; its resource cost does not necessarily increase exponentially with time. However, a contracting prefix reduces the expected fraction of **retained lookup records** even as the underlying chain grows. The index profile is intended to make the end of universal chain-scanned discovery explicit and predictable, not to preserve a permanent comprehensive fallback.

[BRC-49](./0049.md) argues that user-facing addresses should be deprecated and discusses limited tip filtering. [BRC-29](../payments/0029.md), [BRC-42](../key-derivation/0042.md), [BRC-62](../transactions/0062.md), [BRC-95](../transactions/0095.md), and [BRC-100](../wallet/0100.md) provide a direction for receiving transaction data and associated derivation metadata without global address scanning. [BRC-125](../payments/0125.md) defines a URI initiating BRC-29 payments.

This proposal concerns the legacy discovery *index*, not those payment protocols. Providers choosing the profile should communicate its coverage and avoid presenting a filtered result as proof that an unindexed transaction does not exist.

## Specification

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative for implementations that voluntarily claim conformance with this BRC.

### 1. Scope and activation

The **activation block** is BSV mainnet block `1,000,000` (denoted `H0`). The **anchor timestamp** `T0` is the median-time-past (MTP) of `H0`, interpreted in UTC. This makes the anchor an objective chain-derived value rather than the publication date.

A conforming service MUST identify which of these index families it operates:

- **Address index:** generalized lookup of outputs by conventional Base58Check P2PKH address.
- **TXID index:** generalized retrieval or discovery by the conventional displayed TXID.
- **Combined index:** a distinct service that requires matching both address and TXID.

Services MAY implement only one family. A service MUST state its family and current coverage. Consensus validation, block storage, private wallet bookkeeping, merkle-proof processing, and purpose-built overlay indexes are **not** general-purpose indexes governed by this proposal.

For the address family, the stage-0 prefix `1` scopes the profile to conventional mainnet P2PKH addresses, rather than asserting support for every possible locking script.

### 2. Contracting address keyspace

At stage `n`, `0 <= n <= 13`, the allowed address prefix is the first `n + 1` characters of `1ChickenNugget`.

| Stage | Permitted address prefix |
| --- | --- |
| 0 | `1` |
| 1 | `1C` |
| 2 | `1Ch` |
| 3 | `1Chi` |
| 4 | `1Chic` |
| 5 | `1Chick` |
| 6 | `1Chicke` |
| 7 | `1Chicken` |
| 8 | `1ChickenN` |
| 9 | `1ChickenNu` |
| 10 | `1ChickenNug` |
| 11 | `1ChickenNugg` |
| 12 | `1ChickenNugge` |
| 13 | `1ChickenNugget` |

Address prefix matching MUST operate on the canonical, case-sensitive, checksum-valid Base58Check textual address. The final prefix is a filter condition, **not** an instruction for wallets to brute-force vanity keys.

At each active stage a conforming address index MUST NOT answer generalized lookups for records outside its active prefix. It MUST retire excluded records from the *contracting index's* storage; retaining a complete index and only hiding results does not satisfy this storage-retirement profile. The provider MAY maintain other separate data stores, but MUST NOT describe them as conforming contracting indexes.

### 3. Contracting TXID keyspace

At stage `n`, the permitted TXID prefix is `n` consecutive ASCII `9` characters (no requirement at stage 0).

| Stage | Permitted displayed TXID prefix |
| --- | --- |
| 0 | unrestricted |
| 1 | `9` |
| 2 | `99` |
| 3 | `999` |
| 4 | `9999` |
| 5 | `99999` |
| 6 | `999999` |
| 7 | `9999999` |
| 8 | `99999999` |
| 9 | `999999999` |
| 10 | `9999999999` |
| 11 | `99999999999` |
| 12 | `999999999999` |
| 13 | `9999999999999` |

Comparisons MUST use the conventional 64-character big-endian, lowercase hexadecimal **display** representation of the transaction ID. Implementations MUST NOT compare against the beginning of a little-endian internal hash buffer.

A conforming TXID index MUST withdraw and retire generalized TXID-index records not matching the currently active prefix, using the same rules as for the address family.

### 4. Schedule governed by dates and scale

Let `V(H)` be the cumulative count of **non-coinbase transactions** in mainnet blocks with heights `H0 + 1` through `H`, inclusive. At `H0`, `V(H0) = 0`.

For each stage `n` in 1 through 13:

- Earliest date: `T(n) = T0 plus 6*n calendar months`.
- Minimum cumulative volume: `V(n) = 1,000,000 * 2^n` non-coinbase transactions after `H0`.

Calendar-month addition MUST preserve the UTC time of day from `T0`, with day-of-month clamped to the last day of the target month if necessary. For stage `n`, eligibility begins at the first block `H >= H0` where **both** `MTP(H) >= T(n)` and `V(H) >= V(n)`.

The active stage at height `H` is the maximum eligible `n`, or 0 when none qualify. Stages may be skipped if multiple thresholds have been reached when a new block arrives. A chain reorganization MUST cause the service to recompute stage from the accepted chain; this is an explicit exception to monotonicity across competing histories.

| Stage | Earliest elapsed time | Cumulative non-coinbase volume threshold |
| --- | --- | --- |
| 0 | block 1,000,000 | 0 |
| 1 | 6 months | 2,000,000 |
| 2 | 12 months | 4,000,000 |
| 3 | 18 months | 8,000,000 |
| 4 | 24 months | 16,000,000 |
| 5 | 30 months | 32,000,000 |
| 6 | 36 months | 64,000,000 |
| 7 | 42 months | 128,000,000 |
| 8 | 48 months | 256,000,000 |
| 9 | 54 months | 512,000,000 |
| 10 | 60 months | 1,024,000,000 |
| 11 | 66 months | 2,048,000,000 |
| 12 | 72 months | 4,096,000,000 |
| 13 | 78 months | 8,192,000,000 |

Thus full convergence cannot precede 78 calendar months after `T0`; it may occur later, depending on chain transaction counts. A provider MAY independently choose an earlier business sunset for its scanning product but MUST NOT advertise a more advanced **BRC stage** than the algorithm determines.

### 5. Admission, retirement, and query behavior

For a service of the stated family, eligibility at stage `n` is:

```text
addressEligible(address, n) =
  validMainnetP2PKHBase58Check(address)
  AND address.startsWith("1ChickenNugget".slice(0, n + 1))

txidEligible(displayTxid, n) =
  valid64CharacterHexTxid(displayTxid)
  AND lower(displayTxid).startsWith("9".repeat(n))
```

An **address index** MUST apply `addressEligible`; a **TXID index** MUST apply `txidEligible`. A separately identified **combined index** MUST apply both, not an implicit OR rule. Unless explicitly identified as a combined index, the filters are **independent**; the proposal does not require an indexed address output's TXID to match the TXID-index filter.

At every stage change, a service MUST stop admitting excluded entries and MUST retire all excluded entries from the contracting general-purpose index, including historical entries predating `H0`. Retirement MAY be achieved by partition removal or deletion, provided the remaining contracting index no longer holds the excluded entries. An index operator MAY keep underlying blocks, proofs, or independent records for other purposes.

Query responses MUST distinguish:

1. **In scope and found**;
2. **In scope and not found**; and
3. **Outside index coverage**.

A service MUST NOT translate the third state into a claim of nonexistence, invalidity, or lack of payment. Index APIs SHOULD expose `activationHeight`, `activeStage`, `addressPrefix`, `txidPrefix`, `stageBlockHeight`, `chainTipHeight`, and `indexFamily` as machine-readable status.

### 6. Wallet migration and interoperability

Beginning at activation, wallets SHOULD discontinue depending on contracting indexes for payment receipt or wallet restoration. Implementations SHOULD use directly delivered transactions and appropriate payment-remittance metadata. Current BRC-29 / BRC-100 integrations use `createAction`, Atomic BEEF exchange, and `internalizeAction`.

A contracted index is **not** a reliable recovery mechanism for funds sent to arbitrary historical addresses. Wallet operators SHOULD export or preserve the keys, transaction data, derivation parameters, and additional backup material actually necessary to recover controlled outputs. A wallet MUST NOT advertise complete discovery or recovery based solely on a contracted index.

Nothing prevents users from sending to ordinary valid P2PKH addresses. Such outputs simply may not be represented in this restricted lookup product. No wallet is required to generate an address beginning with `1ChickenNugget`, and no sender is required to grind transactions for leading `9`s.

### 7. Security and resource considerations

**Costs.** Each additional required TXID hex digit admits an expected 1/16 of uniformly distributed IDs; at stage 13, the expected fraction is `16^-13`. Address Base58Check prefixes do not have an exact independent 1/58-per-character probability because of encoding, version, and checksum constraints. Implementers MUST NOT use that approximation for correctness tests.

**Very rare survivors.** The final TXID filter admits only approximately one in 4.5 quadrillion uniformly distributed TXIDs. Final-prefix address generation can be extraordinarily expensive. These namespaces are intentionally unsuitable for ordinary wallet discovery.

**Ingestion is not eliminated.** Index admission filtering reduces retained lookup data, but an indexer observing the whole chain may still have to fetch and parse blocks to evaluate eligibility. The BRC makes no claim that prefix constraints themselves eliminate ingestion, validation, or archival storage costs.

**User losses.** Previously publicized deposit addresses may continue receiving valid transactions after an index drops them. Index operators SHOULD prominently publish their support timeline; wallet operators SHOULD migrate before loss of discovery and provide independent recovery routes.

**Censorship and consensus.** Lack of an index hit says nothing about validity. This proposal neither forbids transactions outside the prefixes nor changes consensus or miner requirements. It is a voluntary service conformance profile, not a mechanism to govern what independent parties can store.

**TXID representation.** Mismatched byte order will cause inconsistent results. Conformance tests MUST include display/internal-byte-order differentiation, upper- vs lowercase hex normalization, invalid lengths, stage boundaries, leap-year calendar clamping, and reorganization scenarios.

## Implementations

No implementation or provider commitment is asserted by publication of this draft.

A reference implementation SHOULD include a stage calculator that reads height, median-time-past, and cumulative non-coinbase transaction count; two independent prefix-admission predicates; a safe retention/retirement job; a three-state query API; and tests for stages 0 through 13.

Deployment SHOULD first run in observation mode to estimate what existing clients would lose, then publish migration notices, then enforce the time-and-volume gates. Implementers should test that index deletions do not delete wallet custody records, original blocks, or merkle-proof records used by other services.

## References

- [BRC-16: Pay to Public Key Hash](../scripts/0016.md)
- [BRC-27: Direct Payment Protocol](../payments/0027.md)
- [BRC-28: Paymail Payment Destinations](../payments/0028.md)
- [BRC-29: Simple Authenticated BSV P2PKH Payment Protocol](../payments/0029.md)
- [BRC-42: BSV Key Derivation Scheme](../key-derivation/0042.md)
- [BRC-49: Users should never see an address](./0049.md)
- [BRC-50: Submitting Received Payments to a Wallet (historical)](../wallet/0050.md)
- [BRC-62: BEEF Transactions](../transactions/0062.md)
- [BRC-67: Simplified Payment Verification](../transactions/0067.md)
- [BRC-95: Atomic BEEF Transactions](../transactions/0095.md)
- [BRC-100: Unified Wallet-to-Application Interface](../wallet/0100.md)
- [BRC-125: PeerPay URI Scheme](../payments/0125.md)
