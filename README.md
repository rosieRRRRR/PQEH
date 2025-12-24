# Quantum-Hardened Execution Patterns (QH-EP)

## Execution-Time Hardening for Script-Only Bitcoin Spends (No Wallet-State Enforcement)

**Version:** v2.2.0
**Status:** Advanced Specification
**Author:** rosiea
**Date:** December 2025
**Licence:** Apache License 2.0 — Copyright 2025 rosiea

---

## Summary

BIP-360-style script-only outputs reduce long-range, dormant-UTXO quantum exposure by removing the Taproot key path. This specification addresses the execution window during a spend, when scripts and authorization material are disclosed and the transaction resides in the public mempool.

This document defines Bitcoin-current-consensus execution hardening patterns that:

* deny pre-construction of valid competing spends prior to execution disclosure;
* increase attacker work during the broadcast-to-confirmation window;
* compress effective public-mempool exposure time (Δt_eff) using transaction-set construction and fee packaging;
* provide explicit, pre-constructed recovery paths for stalled spends;
* require no consensus changes and no new opcodes.

This specification does not require any wallet behavior after transaction construction. All enforcement is via (1) Script validity and (2) pre-constructed transaction sets that a broadcaster can submit without further signing.

This work does not claim deterministic prevention of mempool replacement, miner inclusion guarantees, or on-chain post-quantum signatures.

---

## 1. Status

### 1.1 Scope

This specification defines optional execution hardening patterns for BIP-360-style script-only outputs implemented as Taproot/Tapscript spend paths.

It specifies:

* spend-time secret gating (denial of pre-construction);
* secret-keyed key ordering (anti-pretargeting);
* authorization modes (ECC M-of-M and an experimental hash-based mode);
* witness construction rules;
* transaction-set fee packaging (pre-signed CPFP anchor);
* operational discipline (fee strategy, key independence, dry-wallet barrier);
* dual recovery model (timeout return and post-confirmation fallback);
* deterministic failure handling rules expressed as transaction-set constraints (no post-build wallet actions required).

### 1.2 Consensus changes required

None.
All mechanisms herein are valid under current Bitcoin consensus rules (BIP-340/341/342) and standard mempool policy assumptions where applicable.

---

## 2. Execution Scope

This specification applies only to:

* the execution-time, public mempool exposure window;
* spend construction immediately prior to broadcast;
* explicit, pre-constructed recovery paths and fee packages.

This specification does not define custody authority, governance, or temporal oracle semantics.

---

## 3. Threat Model (Normative)

### 3.1 Assumptions

* The attacker can observe the public mempool and attempt replacement via higher-fee spends.
* During execution, scripts and authorization material may be disclosed.
* A quantum-capable attacker may accelerate recovery of ECC private keys during the broadcast-to-confirmation window.
* Bitcoin does not provide deterministic anti-replacement guarantees for general transactions.

### 3.2 Defended Against

This specification mitigates:

* pre-construction of competing spends prior to spend-time disclosure;
* predictable key targeting based on static key order;
* operational exposure due to insufficient feerate and poor propagation;
* quantum-assisted short-range key recovery feasibility by amplifying required authorization work and compressing Δt_eff.

### 3.3 Out of Scope

This specification does not address:

* deterministic prevention of mempool replacement;
* miner-level adversaries or inclusion guarantees;
* covenant-grade destination binding without covenants;
* long-range dormant-UTXO exposure (addressed by BIP-360-style approaches);
* full post-quantum signature security under Bitcoin consensus today.

### 3.4 Multi-Input Fee Sponsorship and Replacement (Normative)

Bitcoin transactions may contain multiple inputs, each governed by independent scripts. QH-EP does not and cannot prevent an adversary who satisfies the authorization requirements of a protected input from adding additional, externally funded inputs to pay fees or to construct a competing transaction.

QH-EP’s security objective is to increase the cost, coordination, and time required to satisfy authorization during the execution window, and to compress Δt_eff via transaction-set fee packaging. It does not provide consensus-level prevention of replacement or deterministic exclusion of multi-input constructions.

---

## 4. Design Principles (Normative)

Mechanisms MUST be:

* consensus-valid on Bitcoin today;
* explicitly scoped to execution-time hardening;
* compatible with Taproot/Tapscript spend paths;
* conservative about guarantees;
* implementable as a pre-constructed transaction set without requiring wallet logic after construction.

Mechanisms MUST NOT be presented as “quantum-proof” or as deterministic prevention of mempool replacement.

---

## 5. Core Definitions (Normative)

### 5.1 Spend-Time Secret (S1)

S1 is a random, one-time secret revealed only at execution.

* S1 MUST be unique per spend attempt.
* S1 MUST NOT be reused.
* H_S1 = SHA256(S1) MUST be committed in the tapleaf script.
* S1 MUST be revealed in the witness only at execution.

### 5.2 Authorization Commitment (AUTH_COMMITMENT)

AUTH_COMMITMENT binds the authorization mode and parameters and MUST commit to:

* selected authorization mode (ECC or hash-based);
* all public parameters needed to validate the mode;
* key ordering and counts where applicable.

### 5.3 Optional Epoch Value (E)

E is an optional wallet-selected coordination value used for auditability and multi-signer alignment.

* Bitcoin Script cannot validate E as time.
* E MUST be canonically encoded (byte-stable across implementations).
* E is used only for context commitment and off-chain coordination. It is not used as a broadcast trigger.

### 5.4 Optional Context Commitment (H_ctx)

If E is used, define:

```
H_ctx = SHA256("QHEP-CTX-V1" || S1 || E || AUTH_COMMITMENT)
```

“QHEP-CTX-V1” is a domain separator.

### 5.5 Transaction Set (TXSET)

A TXSET is a pre-constructed set of one or more fully signed transactions intended to be broadcast together, where the aggregate economic effect improves confirmation probability without requiring any post-build signing.

### 5.6 Effective Exposure Window (Δt_eff)

Δt_eff is the time between public disclosure (first propagation of the spend) and confirmation. TXSET construction and fee packaging are used to compress Δt_eff.

---

## 6. Normative Mechanisms

### 6.1 Denial of Pre-Construction (S1 Gate) (Normative)

All spends implementing this specification MUST include a spend-time secret gate:

```
OP_SHA256 <H_S1> OP_EQUALVERIFY
```

Security objective:

* prevent third parties from constructing a valid competing spend prior to S1 disclosure.

### 6.2 Optional Context Binding (EPOCH-Style Commitment) (Normative–Optional)

If E is used, the script MUST verify H_ctx immediately after S1 verification:

```
OP_SHA256 <H_ctx> OP_EQUALVERIFY
```

Requirements:

* E MUST be canonically encoded.
* AUTH_COMMITMENT MUST bind the authorization mode and parameters.

Security objective:

* tamper-evident binding of intended execution context without claiming Script oracle properties.

### 6.3 Secret-Keyed Ordering (Normative)

If a script uses multiple public keys for authorization, the ordering of those keys MUST be derived from a one-time secret S1 revealed only at execution.

Define:

* ordering_secret = SHA256("QHEP-Key-Order" || S1)
* tag_i = HMAC-SHA256(ordering_secret, pubkey_i_bytes)
* ordered_keys = sort_by(tag_i)

Security objective:

* prevent attackers from pre-selecting or prioritizing specific keys prior to execution disclosure;
* reduce the value of advance targeting and staged preparation.

This mechanism does not prevent sequential key recovery after S1 revelation.

---

## 7. Authorization Modes (Normative)

### 7.1 Production Mode (ECC, M-of-M) (Normative)

Authorization uses M-of-M Schnorr checks via OP_CHECKSIGADD:

```
<K1_xonly> OP_CHECKSIG
<K2_xonly> OP_CHECKSIGADD
...
<KM_xonly> OP_CHECKSIGADD
<M> OP_NUMEQUAL
```

Requirements:

* AUTH_COMMITMENT MUST bind the ordered x-only pubkeys and M-of-M parameters.
* Keys MUST be independent (see §10.2).

Properties:

* compatible with Taproot/Tapscript tooling;
* increases attacker workload proportional to M;
* ECC is exposed during execution.

### 7.2 Research Mode (Hash-Based Authorization) (Normative–Experimental)

STATUS: EXPERIMENTAL — NOT FOR PRODUCTION USE

WARNING: Hash-based authorization is strictly one-shot. Any revealed preimages are permanently public and MUST be treated as irreversibly burned. Reuse, partial reuse, or failed execution MAY result in permanent loss of funds. This mode incurs large witness sizes, high fees, and removes any ability to rely on replacement or fee adjustment after broadcast.

---

## 8. Script Templates (Normative)

### 8.1 Primary Leaf Prefix (Normative)

All compliant primary tapleaf scripts MUST begin with:

```
OP_SHA256 <H_S1> OP_EQUALVERIFY
[ OPTIONAL: OP_SHA256 <H_ctx> OP_EQUALVERIFY ]
# Authorization follows
```

### 8.2 Example Primary Leaf (ECC, M-of-M) (Normative)

```
OP_SHA256 <H_S1> OP_EQUALVERIFY
OP_SHA256 <H_ctx> OP_EQUALVERIFY
<K1_xonly> OP_CHECKSIG
<K2_xonly> OP_CHECKSIGADD
...
<KM_xonly> OP_CHECKSIGADD
<M> OP_NUMEQUAL
```

---

## 9. Witness Stack Construction (Normative)

### 9.1 Witness Ordering Rule (Normative)

For OP_CHECKSIGADD scripts, signatures MUST be pushed to the witness stack in reverse order of the public keys as they appear in the script.

### 9.2 Primary Spend Witness Stack (Normative)

Witness stack (top to bottom):

```
[ sig_M ] ... [ sig_1 ]
[ E (optional) ]
[ S1 ]
[ script ]
[ control_block ]
```

Requirements:

* S1 MUST satisfy H_S1.
* If present, E MUST match the encoding used in H_ctx.
* Authorization material MUST match AUTH_COMMITMENT.

---

## 10. Operational Discipline (Normative)

### 10.1 Dry-Wallet Barrier (Normative)

All signing wallets used in execution hardening MUST maintain a zero on-chain balance.

Fee funding MUST occur from a separate fee wallet that is not used as an execution signer.

### 10.2 Key Independence (Normative)

Signers MUST use truly independent signing keys, derived from independent entropy sources and, where practical, separate devices and administrative domains.

### 10.3 Signature Binding (Normative)

Production Mode signatures MUST use SIGHASH_ALL unless an implementation profile explicitly and normatively specifies an alternative binding mode and demonstrates that the binding remains consistent with the threat model.

---

## 11. TXSET Fee Packaging Profile (Normative)

### 11.1 Objective

Increase confirmation probability and compress Δt_eff without post-build signing by broadcasting a pre-constructed package that includes an immediately valid CPFP child spending a pre-committed anchor output.

### 11.2 TXSET Structure (Normative)

A TXSET MAY include:

* T_main — the primary spend from the protected BIP-360 output(s).
* T_cpfp0 — an immediately valid CPFP child spending an anchor output created by T_main.

T_main and T_cpfp0 MUST be fully signed and complete at build time.

### 11.3 Anchor Output (Normative)

If TXSET fee packaging is used, T_main MUST include a designated anchor output:

* value: deployment-defined;
* script: controlled by a distinct fee-sponsor key set (recommended), not by execution signers;
* spend policy: must be immediately spendable by T_cpfp0 without requiring any additional signatures after build time.

**The anchor output value MUST be at least the prevailing dust threshold for its script type and SHOULD be ≥330 satoshis.**

The anchor output exists solely to allow CPFP package fee dominance without needing wallet behavior after construction.

### 11.4 CPFP Child Transaction (Normative)

T_cpfp0 MUST:

* spend the anchor output of T_main;
* pay a fee sufficient to raise the effective package feerate to the target next-block region with conservative headroom;
* be valid immediately (no CSV/CLTV gates);
* be fully signed at build time.

### 11.5 Broadcast Rule (Normative)

When using TXSET packaging, a broadcaster MUST broadcast:

* T_main and T_cpfp0 together, as close in time as possible.

The broadcaster MAY be any component or operator holding the completed TXSET. No additional signing is permitted or required after build.

### 11.6 Limits (Normative)

TXSET packaging:

* does not guarantee inclusion;
* does not prevent a higher-fee conflicting spend if an attacker can authorize it;
* must not be described as a deterministic replacement prevention mechanism.

---

## 12. Dual Recovery Model (Normative)

### 12.1 Unmined Timeout Return (Normative)

A recovery path MAY be committed at output creation time.

Example:

```
<H_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
<R1_pub> OP_CHECKSIG
<R2_pub> OP_CHECKSIGADD
...
<RR_pub> OP_CHECKSIGADD
<R> OP_NUMEQUAL
```

Requirements:

* Recovery keys MUST be independent from execution keys.
* H_timeout MUST be selected conservatively to avoid premature recovery races.
* This leaf MUST be explicitly committed at output creation time.

### 12.2 Post-Confirmation Fallback (Normative–Optional)

If used, this path MUST be explicitly pre-constructed and policy-approved and MUST NOT create an alternative authority path.

---

## 13. Failure Handling (Normative)

Because no wallet behavior is assumed after build, failure handling is expressed as TXSET and key-management requirements at build time.

On any failure observed by operators or monitoring systems:

* all attempt material (including S1) MUST be treated as permanently burned;
* any reattempt MUST be constructed as a fresh TXSET under fresh randomness and fresh keys where applicable;
* partial reuse is forbidden.

For hash-based authorization spends, any revealed preimages MUST be treated as permanently burned regardless of confirmation outcome.

---

## 14. Quantitative Condition (Informative)

Execution-layer hardening improves security when the attacker’s effective key-recovery time during execution approaches or exceeds the expected broadcast-to-confirmation window.

Security improves as:

* attacker key-recovery time increases;
* required independent authorizations (M) increases; and
* Δt_eff is compressed via fee packaging and propagation discipline.

Bitcoin block discovery is probabilistic. No closed-form inequality provides guaranteed safety.

---

## 15. Non-Goals (Normative)

This specification does not:

* provide deterministic prevention of mempool replacement;
* guarantee miner inclusion;
* provide covenants or destination enforcement;
* claim on-chain post-quantum signature security.

---

## 16. Relationship to BIP-360 (Informative)

BIP-360-style script-only outputs reduce long-range quantum exposure at rest by removing the key path. This specification complements that approach by hardening the execution window during spends.

At-rest protection and execution-time hardening are distinct and non-substitutable.

---

## 17. Conformance Requirements (Normative)

An implementation claiming QH-EP v2.2.0 conformance MUST:

1. Use BIP-360 script-only outputs (or explicitly declare equivalent rest-state behavior).
2. Implement the spend-time secret gate (S1) in the primary leaf.
3. If multi-key authorization is used, implement secret-keyed ordering derived from S1.
4. For production mode, implement ECC M-of-M authorization.
5. Use SIGHASH_ALL unless an explicitly declared alternative is justified and specified.
6. If TXSET fee packaging is claimed, construct T_main + T_cpfp0 as a fully signed TXSET at build time.
7. Implement recovery paths only if pre-committed at output creation time; recovery keys must be independent.
8. Treat all revealed attempt material as burned; reattempts must be fresh TXSETs.

Implementations MUST NOT claim deterministic replacement prevention, deterministic inclusion, or “quantum-proof” protection under this specification.

---

## 18. Security Considerations (Normative)

This section summarizes security-relevant assumptions and constraints already defined elsewhere in this specification. It introduces no new mechanisms.

### 18.1 Quantum Threat Assumptions

QH-EP assumes a short-range quantum threat model in which adversaries may accelerate recovery of classical ECC private keys during the execution window after public disclosure of authorization material. This specification does not address long-range at-rest exposure or on-chain post-quantum signatures.

### 18.2 Execution-Window Scope

All protections apply only during the broadcast-to-confirmation window. Once a transaction is confirmed, QH-EP provides no additional security properties beyond standard Bitcoin consensus.

### 18.3 Replacement and Inclusion Limits

QH-EP does not guarantee prevention of mempool replacement, miner inclusion, or fee dominance. Transaction-set fee packaging increases economic pressure but does not provide deterministic guarantees.

### 18.4 Operational Risks

Improper fee estimation, correlated signer keys, signer compromise, or reuse of attempt material may materially reduce security. Operators are responsible for enforcing key independence, sufficient initial feerates, and strict single-use semantics for spend-time secrets.

### 18.5 No Wallet-State Enforcement

This specification intentionally assumes no wallet behavior after transaction construction. All security properties depend on correct pre-construction of scripts, witnesses, transaction sets, and recovery paths.

---

## 19. Informative References

* BIP-340 — Schnorr Signatures for secp256k1
* BIP-341 — Taproot: SegWit version 1 spending rules
* BIP-342 — Validation of Taproot Scripts
* BIP-360 — Script-only Taproot outputs (P2TSH)
* Bitcoin Core Mempool Policy Documentation
* Bitcoin Core Child-Pays-For-Parent (CPFP) Policy and Package Relay Notes

---

## Appendix A — Implementation Examples (Informative)

This appendix is **non-normative** and provided for developer comprehension only.
Examples MUST NOT be interpreted as prescriptive, complete, or exhaustive.

### A.1 Illustrative Miniscript Sketch (Non-Normative)

An example conceptual Miniscript representation of a primary tapleaf using an S1 gate and M-of-M authorization:

```
sha256(H_S1) &&
sha256(H_ctx) &&
multi_a(M, K1, K2, ... KM)
```

This sketch is illustrative only. Actual Miniscript encodings, key ordering, and Taproot commitments MUST conform to the normative requirements defined in Sections 6–9 of this specification.

### A.2 Illustrative TXSET Construction Flow (Non-Normative)

A typical TXSET construction sequence:

1. Construct `T_main`:

   * Spend protected BIP-360 output.
   * Include S1-gated primary tapleaf.
   * Include designated anchor output.
   * Fully sign all inputs.

2. Construct `T_cpfp0`:

   * Spend the anchor output from `T_main`.
   * Set fee to achieve target effective package feerate.
   * Fully sign at build time.

3. Package `{ T_main, T_cpfp0 }` as a TXSET.

4. Broadcast both transactions together.

No signing, mutation, or fee adjustment is permitted after build.

### A.3 Witness Validation Checklist (Non-Normative)

Implementers may validate:

* S1 preimage matches committed `H_S1`.
* Optional `E` encoding matches that used in `H_ctx`.
* AUTH_COMMITMENT parameters match script expectations.
* Signatures are ordered correctly for OP_CHECKSIGADD evaluation.
* No attempt material is reused across spend attempts.

---

## Appendix B — Applicability Guide (Informative)

This appendix provides **operational guidance only** and does not affect conformance.

### B.1 When QH-EP Is Appropriate

QH-EP may be appropriate in environments with one or more of the following characteristics:

* High-value Bitcoin spends.
* Multi-signer authorization paths (M ≥ 2).
* Adversarial mempool observation is a credible concern.
* Requirement for explicit, pre-constructed recovery paths.
* Desire to reduce execution-window exposure without wallet interactivity.

### B.2 When QH-EP May Be Inappropriate

QH-EP may be inappropriate where:

* Transaction values are low and execution risk is negligible.
* Single-signature authorization is used without signer diversity.
* Operational complexity outweighs execution-time risk.
* Fee estimation and propagation discipline cannot be reliably enforced.

---

## Appendix C — Versioning Notes (Informative)

This specification follows semantic versioning.

* Patch versions MAY clarify language or examples without altering normative requirements.
* Minor versions MAY add optional mechanisms or appendices.
* Major versions MAY introduce incompatible changes and will require explicit migration.

No backward compatibility guarantees are implied beyond those explicitly stated.

---

## Acknowledgements

This work builds on decades of research and practice in cryptography, distributed systems, and the design and operation of the Bitcoin protocol.

The author acknowledges the foundational contributions of:

* **Satoshi Nakamoto** for the original design of Bitcoin;
* **Hal Finney** for early implementation and applied cryptographic insight;
* **Adam Back** for Hashcash and proof-of-work systems;
* **Pieter Wuille** for hierarchical deterministic wallets, SegWit, Taproot, Miniscript, and PSBT semantics;
* **Greg Maxwell** for adversarial analysis and Bitcoin security research;
* **Andrew Poelstra** for formal reasoning about Bitcoin script and spend-policy composability;
* **Ralph Merkle** for Merkle trees;
* **Whitfield Diffie and Martin Hellman** for public-key cryptography;
* **Peter Shor** for demonstrating the impact of quantum computation on classical cryptography;
* **Daniel J. Bernstein** for cryptographic engineering; and
* the **NIST Post-Quantum Cryptography Project** for the standardisation of post-quantum cryptographic primitives.

Acknowledgement is also due to contributors to the Bitcoin protocol and BIP process whose work on execution-time exposure, mempool policy, and conservative hardening helped clarify scope, terminology, and design discipline.

Any errors, omissions, or remaining ambiguities remain the responsibility of the author.

---



