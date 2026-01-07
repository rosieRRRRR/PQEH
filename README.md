# PQEH – Post-Quantum Execution Hardening

* **Specification Version:** 2.1.1
* **Status:** Public beta
* **Date:** 2026
**Author:** rosiea
**Contact:** [PQRosie@proton.me](mailto:PQRosie@proton.me)
**Licence:** Apache License 2.0 — Copyright 2026 rosiea

---

## Summary

PQEH defines post-quantum execution hardening patterns for Bitcoin that deny pre-construction attacks. The S1/S2 revelation pattern separates commitment (non-executable S1) from execution revelation (S2), ensuring no executable transaction exists before PQSEC authorization. This reduces the quantum attack window from signing-to-confirmation to broadcast-to-confirmation—often under 1 second. PQEH provides execution-layer hardening for current Bitcoin consensus without requiring protocol changes. It does not provide full post-quantum immunity (a Bitcoin consensus limitation), but represents state-of-the-art denial-of-pre-construction within consensus constraints.

**Key Properties:** S1/S2 revelation pattern | Pre-construction denial | Quantum window reduction | No consensus changes required | Explicit limitation acknowledgment | Execution patterns only

---

## 1A. Canonical Scope and Limitation Disclaimer (Normative)

PQEH does not claim censorship resistance, miner-inclusion guarantees, replacement-proof execution, or post-broadcast quantum immunity.

PQEH defines execution hardening patterns only. It does not grant authority, does not evaluate policy, and does not authorize execution. PQEH reveals execution capability solely after receipt and verification of a valid EnforcementOutcome produced by PQSEC.

Any reduced-exposure or denial-of-pre-construction property is conditional on correct composition with:

* ZET execution boundary semantics,
* ZEB broadcast discipline and observation,
* strict attempt-scoped burn discipline, and
* minimization of the revelation-to-broadcast interval.

These properties are not standalone guarantees and MUST NOT be represented as quantum immunity or inclusion assurance.

---

## Non-Normative Overview — For Explanation and Orientation Only

**This section is NOT part of the conformance surface.  
It is provided for explanatory and onboarding purposes only.**

### Plain Summary

PQEH defines post-quantum execution hardening for Bitcoin that denies
pre-construction and pre-broadcast attacks. It specifies how execution
capability is revealed only after external enforcement approval.
PQEH does not provide custody authority and does not claim post-broadcast
quantum immunity.

### What PQEH Is / Is Not

| PQEH IS | PQEH IS NOT |
|----------|--------------|
| An execution pattern specification | A custody authority system |
| A pre-construction denial mechanism | A post-broadcast protector |
| An S1/S2 revelation protocol | A quantum-immune algorithm |
| A hardening layer | A Bitcoin consensus change |

### Canonical Flow (Single Line)

S1 Commitment (non-executable) → PQSEC Approval → S2 Revelation → Broadcast

### Why This Exists

PQEH exists to reduce the quantum attack window for Bitcoin
transactions. Classical Bitcoin signatures are authoritative artefacts
that can be observed before broadcast, enabling pre-construction and
front-running attacks. By separating commitment (S1) from execution
revelation (S2), PQEH ensures no executable transaction exists before
enforcement approval, reducing quantum exposure to the broadcast-to-
confirmation window rather than the signing-to-confirmation window.

---

## 1. Scope and Execution Boundary

PQEH defines **Bitcoin transaction execution hardening patterns only**.

PQEH normatively defines:

* pre-signing protocols for quantum-resistant commitment
* S1/S2 revelation pattern for denial-of-pre-construction
* deterministic execution ordering and atomicity requirements
* transaction malleability mitigation patterns
* script template validation and binding
* execution failure modes and abort semantics
* canonical execution trace requirements

**Execution Boundary:**
PQEH defines Bitcoin transaction execution patterns consumed after PQSEC authorization.

**Enforcement Boundary:**
PQEH does not perform enforcement, gating, refusal, escalation, lockout, custody authority evaluation, time anchoring, or admission control. All such behaviour is defined exclusively by PQSEC and custody specifications.

Any implementation performing enforcement, custody decisions, or authority evaluation inside PQEH is architecturally non-conformant.

---

## 2. Non Goals and Authority Prohibition

PQEH does not define:

* custody authority, signing authorization, or quorum decisions
* predicate evaluation, refusal logic, or enforcement decisions
* mempool strategy, fee estimation, or miner interaction
* relay policy, transaction propagation, or broadcast protocol
* runtime integrity probing or attestation generation
* time anchoring, issuance, or freshness enforcement
* AI behaviour, model inference, or alignment
* transport protocols or session establishment
* block confirmation thresholds or finality interpretation

**Authority Prohibition:**
PQEH grants no authority, makes no decisions, and performs no enforcement. PQEH defines execution patterns only. Authority derives exclusively from PQSEC enforcement of custody predicates defined by PQHD.

---

## 3. Threat Model

PQEH assumes adversaries may:

* possess future quantum computation capability sufficient to break ECDSA
* attempt transaction malleability attacks
* attempt pre-construction of transactions before authorization
* exploit script template ambiguities
* reorder or replay execution attempts
* corrupt or substitute execution artefacts
* compromise execution environment

PQEH does not assume trusted execution environments, trusted coordinators, or honest relay nodes.

---

## 4. Trust Assumptions

PQEH operates under the following trust assumptions:

* Bitcoin blockchain consensus is honest majority
* Script evaluation is deterministic per Bitcoin Core reference implementation
* Quantum adversaries cannot invert hash functions (SHA256, RIPEMD160)
* S1 revelation enforces temporal ordering (pre-image resistance)
* PQSEC authorization precedes all execution
* Custody authority is evaluated externally by PQSEC + PQHD

---

## 5. Architecture Overview

PQEH defines post-quantum execution hardening consisting of:

* **Pre-Signing Protocol**
  Quantum-resistant commitment via Taproot with post-quantum signature binding.

* **S1/S2 Revelation Pattern**
  Denial of pre-construction until S1 revelation provides atomic commit.

* **Execution Ordering Layer**
  Deterministic step sequencing and atomicity guarantees.

* **Script Template Layer**
  Canonical script templates with binding validation.

* **Failure Handling Layer**
  Deterministic abort semantics and recovery patterns.

PQEH defines execution hardening only. PQEH does not define operational behaviour or enforcement semantics.

---

## 5A. Explicit Dependencies

| Specification | Minimum Version | Purpose |
|---------------|-----------------|---------|
| PQSEC | ≥ 2.0.1 | Enforcement approval before S2 revelation |
| PQHD | ≥ 1.1.0 | Custody predicate satisfaction |
| ZET/ZEB | ≥ 1.2.0 | Execution boundary and broadcast discipline |
| Epoch Clock | ≥ 2.1.1 | Tick-based execution timing |

PQEH defines execution patterns only. Custody authority is defined by PQHD and enforced by PQSEC.

---

## 6. Conformance Keywords

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119.

---

## 7. Threat: Quantum Pre-Construction

### 7.1 Attack Vector

A quantum adversary with sufficient capability can:

1. Observe a prepared Bitcoin transaction with classical ECDSA signatures
2. Use quantum computation to derive private keys from public keys
3. Construct alternative transactions spending the same inputs
4. Broadcast competing transactions to double-spend

### 7.2 Traditional Defenses (Insufficient)

* **Post-Quantum Signatures**: Bitcoin does not natively support PQ signatures
* **Script Hardening**: Script alone cannot prevent quantum key derivation
* **Time Locks**: Time locks do not prevent quantum key compromise

### 7.3 PQEH Defense Strategy

PQEH mitigates quantum pre-construction via:

1. **S1/S2 Revelation Pattern**: Transaction construction impossible until S1 revealed
2. **Minimal Exposure Window**: S1 revealed only when ready to broadcast
3. **Atomic Revelation**: S1 and broadcast occur in rapid succession
4. **No Pre-Signed State**: Transaction exists only after S1 revelation

---

## 8. S1/S2 Revelation Pattern

### 8.1 Pattern Overview

The S1/S2 revelation pattern provides **denial of pre-construction**:

1. **S1 (Secret 1)**: High-entropy secret held by authorizer, never revealed until execution
2. **S2 (Secret 2)**: Derived from S1, embedded in script commitment
3. **Execution Gate**: Transaction cannot be constructed without S1
4. **Revelation**: S1 revealed only at execution time, enabling atomic broadcast

### 8.2 S1 Generation

```python
S1 = CSPRNG(256 bits)
```

Requirements:
* S1 MUST be generated from cryptographically secure random number generator
* S1 MUST have at least 256 bits of entropy
* S1 MUST be unique per transaction attempt
* S1 MUST be stored securely until revelation time

### 8.3 S2 Derivation

```python
S2 = SHA256(S1)
```

Requirements:
* S2 MUST be derived deterministically from S1
* S2 MUST be embedded in script template before authorization
* S2 serves as commitment to S1
* Pre-image resistance prevents S1 derivation from S2

### 8.4 Script Template with S2 Commitment

```
OP_SHA256 <S2> OP_EQUALVERIFY
<pubkey> OP_CHECKSIG
```

This script requires:
1. Witness provides S1
2. SHA256(S1) == S2
3. Valid signature over spending transaction

Without S1, the transaction cannot be constructed.

### 8.5 Revelation Timing

**Critical Timing Requirements:**

1. S1 MUST NOT be revealed before PQSEC authorization
2. S1 MUST NOT be revealed before ready to broadcast
3. S1 revelation and transaction broadcast MUST occur atomically
4. Time between S1 revelation and broadcast MUST be minimized (target: < 1 second)

### 8.6 Revelation Protocol

```
1. Custody authorization obtained (PQSEC + PQHD)
2. Transaction template prepared (with S2 in script)
3. S1 revealed to transaction construction component
4. Transaction constructed with S1 in witness
5. Transaction signed with custody keys
6. Transaction broadcast immediately via ZEB
```

---

## 9. Taproot Integration

### 9.1 Taproot Spend Path

PQEH uses Taproot for post-quantum execution hardening:

**Key Path (Primary):**
* Internal key: Post-quantum key commitment (not directly spendable via ECDSA)
* Requires script path spend

**Script Path (Post-Quantum Hardened):**
* Script includes S2 commitment
* Script requires S1 revelation
* Script includes post-quantum signature verification (via delegation pattern)

### 9.2 Taproot Construction

```python
def construct_taproot_output(pq_pubkey: bytes, S2: bytes) -> bytes:
    """
    Construct Taproot output with quantum hardening.
    """
    # Internal key (tweaked, not directly spendable)
    internal_key = compute_internal_key(pq_pubkey)
    
    # Script with S2 commitment
    script = build_s1_s2_script(S2, pq_pubkey)
    
    # Taproot commitment
    taproot_commitment = compute_taproot_commitment(internal_key, script)
    
    # Output script
    output_script = build_taproot_output_script(taproot_commitment)
    
    return output_script
```

### 9.3 Taproot Spending

```python
def construct_taproot_spend(
    S1: bytes,
    pq_signature: bytes,
    script: bytes,
    control_block: bytes
) -> bytes:
    """
    Construct Taproot script path spend with S1 revelation.
    """
    witness = [
        pq_signature,
        S1,
        script,
        control_block
    ]
    
    return serialize_witness(witness)
```

---

## 10. Execution Ordering and Atomicity

### 10.1 Deterministic Execution Order

PQEH execution MUST follow strict ordering:

```
1. PQSEC Authorization
   └─> EnforcementOutcome = ALLOW

2. S1 Revelation
   └─> S1 released to transaction builder

3. Transaction Construction
   └─> PSBT constructed with S1 in witness

4. Custody Signing
   └─> M-of-N signatures collected (PQHD)

5. Transaction Finalization
   └─> Signatures aggregated into final transaction

6. Broadcast (ZEB)
   └─> Transaction broadcast via encrypted channels

7. Confirmation Monitoring
   └─> Monitor for inclusion in blockchain
```

### 10.2 Atomicity Requirements

1. **S1 Revelation Atomicity**: S1 revelation and transaction construction MUST be atomic (no interruption)
2. **Signing Atomicity**: All M-of-N signatures MUST be collected or operation aborted
3. **Broadcast Atomicity**: Transaction broadcast MUST complete or operation aborted
4. **No Partial State**: Intermediate state MUST NOT be persisted on failure

### 10.3 Abort Conditions

Execution MUST abort on:

* PQSEC denial (EnforcementOutcome != ALLOW)
* S1 revelation failure
* Transaction construction failure
* Custody signing failure (quorum not met)
* Broadcast failure (all channels exhausted)
* EnforcementOutcome expiry

---

## 11. Pre-Signing Protocol

### 11.1 Pre-Signing Overview

Pre-signing enables preparation of transaction structure before final authorization:

1. **Template Phase**: PSBT created with S2 commitment, no S1
2. **Authorization Phase**: PQSEC evaluates custody predicates
3. **Revelation Phase**: S1 revealed, transaction constructed
4. **Signing Phase**: Custody keys sign final transaction

### 11.2 Pre-Signing Requirements

1. Pre-signed templates MUST include S2 in script
2. Pre-signed templates MUST NOT include S1
3. Pre-signed templates MUST be bound to specific inputs/outputs
4. Pre-signing MUST NOT bypass custody authorization

### 11.3 Template Binding

Templates MUST be bound to:

* Input UTXOs (txid:vout)
* Output addresses and amounts
* Fee rate
* Locktime
* Sequence values

Any deviation MUST invalidate the template.

---

## 12. Script Template Validation

### 12.1 Canonical Script Templates

PQEH defines canonical script templates:

**Template 1: S1/S2 with Single Key**
```
OP_SHA256 <S2> OP_EQUALVERIFY
<pubkey> OP_CHECKSIG
```

**Template 2: S1/S2 with M-of-N Multisig**
```
OP_SHA256 <S2> OP_EQUALVERIFY
<M> <pubkey1> <pubkey2> ... <pubkeyN> <N> OP_CHECKMULTISIG
```

**Template 3: S1/S2 with Taproot Script**
```
OP_SHA256 <S2> OP_EQUALVERIFY
<internal_key> OP_CHECKSIGVERIFY
<delegation_data> OP_DROP
```

### 12.2 Template Validation Rules

1. Templates MUST match canonical forms exactly
2. Templates MUST include S2 commitment
3. Templates MUST include valid public keys
4. Templates MUST NOT contain OP_RETURN or non-standard opcodes
5. Templates MUST pass Bitcoin Core IsStandard() checks

### 12.3 Template Instantiation

Template instantiation:

1. Select canonical template
2. Substitute S2 = SHA256(S1)
3. Substitute public keys from custody configuration
4. Validate template structure
5. Commit template to PSBT

---

## 13. Transaction Malleability Mitigation

### 13.1 Malleability Vectors

PQEH mitigates:

* **Signature Malleability**: Use BIP 62 / BIP 66 compliant signatures
* **Script Malleability**: Use SegWit / Taproot (witness segregation)
* **Input Order Malleability**: Enforce deterministic input ordering
* **SIGHASH Malleability**: Use SIGHASH_ALL exclusively for Authoritative operations

### 13.2 Deterministic Input Ordering

Inputs MUST be ordered by:

1. Lexicographic ordering of (txid, vout) pairs
2. Ascending order

### 13.3 Deterministic Output Ordering

Outputs MUST be ordered by:

1. Ascending output value
2. Lexicographic ordering of scriptPubKey (for equal values)

### 13.4 SIGHASH Requirements

For Authoritative operations:
* MUST use SIGHASH_ALL (0x01)
* MUST NOT use SIGHASH_ANYONECANPAY
* MUST NOT use SIGHASH_SINGLE or SIGHASH_NONE

---

## 14. Execution Trace

### 14.1 Trace Structure

```
ExecutionTrace = {
  trace_id: tstr,
  attempt_id: tstr,
  enforcement_outcome_id: tstr,
  steps: [* ExecutionStep],
  final_txid: bstr / null,
  status: "COMPLETED" / "ABORTED" / "FAILED",
  issued_tick: uint,
  signature: bstr
}

ExecutionStep = {
  step: "authorization" / "s1_revelation" / "construction" / 
        "signing" / "broadcast" / "confirmation",
  timestamp_tick: uint,
  duration_ms: uint,
  status: "SUCCESS" / "FAILURE",
  error_code: tstr / null
}
```

### 14.2 Trace Requirements

1. ExecutionTrace MUST be canonical CBOR (per PQSF)
2. ExecutionTrace MUST record all execution steps
3. ExecutionTrace MUST be signed for auditability
4. ExecutionTrace MUST be recorded in custody ledger

### 14.3 Trace Recording

Traces MUST be recorded for:

* All Authoritative operations (REQUIRED)
* Failed execution attempts (REQUIRED)
* Aborted operations (REQUIRED)
* Non-Authoritative operations (OPTIONAL)

---

## 15. Failure Modes

### 15.1 Authorization Failure

**Condition**: PQSEC returns EnforcementOutcome != ALLOW

**Handling**:
1. Abort immediately
2. Do NOT reveal S1
3. Record failure in trace
4. Return error to caller

### 15.2 S1 Revelation Failure

**Condition**: S1 cannot be retrieved or decrypted

**Handling**:
1. Abort immediately
2. Record failure in trace
3. Escalate to recovery procedures

### 15.3 Construction Failure

**Condition**: Transaction construction fails (invalid template, insufficient funds, etc.)

**Handling**:
1. Abort immediately
2. S1 MAY be discarded or retained for retry
3. Record failure in trace

### 15.4 Signing Failure

**Condition**: Custody quorum not met

**Handling**:
1. Abort transaction
2. S1 MUST be discarded
3. Retry requires new S1 and new authorization

### 15.5 Broadcast Failure

**Condition**: All broadcast channels fail

**Handling**:
1. Transaction MAY be retained for retry
2. Retry broadcast via alternate channels
3. If retry fails, abort and generate new transaction

---

## 16. Epoch Clock Integration

1. PQEH MUST consume time artefacts via PQSEC.
2. PQEH MUST NOT transform, canonicalize, hash, or re-encode Epoch Clock artefacts.
3. All temporal binding (issued_tick, timestamp_tick) uses Epoch Clock ticks.
4. Epoch Clock handling semantics are defined by PQSF and PQSEC.

---

## 17. Error Handling

### 17.1 Error Code Mapping

PQEH failures map to PQSEC error codes:

* S1 revelation failure → E_EXECUTION_S1_REVELATION_FAILED
* construction failure → E_EXECUTION_CONSTRUCTION_FAILED
* signing quorum failure → E_QUORUM_INSUFFICIENT
* broadcast failure → E_BROADCAST_FAILED
* template validation failure → E_EXECUTION_TEMPLATE_INVALID
* malleability detected → E_EXECUTION_MALLEABILITY_DETECTED

### 17.2 Error Propagation

PQEH MUST NOT define new error codes. All errors MUST use PQSEC error code vocabulary.

---

## 18. Dependency Boundaries

1. PQEH MUST receive authorization from PQSEC before execution.
2. PQEH MUST receive custody authority from PQHD via PQSEC.
3. PQEH MUST hand off broadcast to ZEB after transaction finalization.
4. PQEH MUST consume canonical encoding rules via PQSF.
5. PQEH MUST consume time semantics via Epoch Clock and PQSEC.

---

## 19. Failure Semantics

1. Any authorization, S1 revelation, construction, signing, or broadcast failure MUST result in abort.
2. Partial execution MUST NOT leave persistent state.
3. No degraded modes or fallback execution patterns are permitted.
4. All enforcement occurs in PQSEC.

---

## 20. Threat Model Limitations

### 20.1 What PQEH Prevents

* Quantum pre-construction of transactions
* Unauthorized transaction execution
* Transaction malleability attacks
* Replay of execution attempts

### 20.2 What PQEH Does NOT Prevent

* Quantum attacks on already-broadcast transactions (mempool/blockchain)
* Quantum attacks after S1 revelation (exposure window exists)
* Social engineering or coercion attacks
* Compromise of custody keys themselves

### 20.3 Acknowledged Trade-offs

**Security vs Usability:**
* S1/S2 pattern adds complexity
* Requires careful key management
* Revelation timing is critical

**Quantum Resistance Level:**
* PQEH provides "denial of pre-construction" only
* Not full quantum immunity (Bitcoin itself is not quantum-immune)
* Meaningful against TL1 adversaries (pre-quantum-ready adversaries)
* Insufficient against TL2 adversaries (post-CRQC, require protocol-level PQ)

---

## 21. Conformance

An implementation is PQEH conformant if it:

* enforces S1/S2 revelation pattern
* enforces deterministic execution ordering
* enforces atomicity requirements
* enforces script template validation
* enforces malleability mitigation
* delegates authorization to PQSEC
* produces deterministic traces for identical inputs

---

## 22. Security Considerations

### 22.1 Threats Addressed

PQEH addresses the following threats within its defined scope:

- **Pre-construction attacks:**  
  By separating commitment (S1) from execution revelation (S2), PQEH
  ensures no executable transaction exists before enforcement approval.

- **Front-running triggered by early signatures:**  
  S1 artefacts are non-executable and non-authoritative, preventing
  attackers from constructing a valid spend prior to S2 revelation.

- **Quantum pre-exposure window expansion:**  
  PQEH reduces the quantum attack window to the broadcast-to-confirmation
  interval, rather than the signing-to-confirmation interval.

### 22.2 Threats NOT Addressed (Out of Scope)

PQEH does NOT protect against:

- **Post-broadcast quantum attacks:**  
  Once S2 is revealed and broadcast, signatures are exposed as in
  standard Bitcoin transactions.

- **Key compromise prior to enforcement:**  
  Custody authority and key protection are handled by PQHD and enforced
  by PQSEC.

- **Miner censorship or inclusion manipulation:**  
  PQEH does not provide censorship resistance guarantees.

- **Transaction confidentiality:**  
  PQEH provides no privacy or metadata protection.

### 22.3 Authority Boundary

PQEH grants no custody authority and performs no enforcement.

Authority derives exclusively from:
- PQSEC enforcement outcomes
- PQHD custody predicates
- Epoch Clock time artefacts (indirectly)

PQEH MUST NOT be treated as an authorization or policy enforcement
mechanism.

### 22.4 Fail-Closed Semantics

If S2 revelation does not occur following enforcement approval:
- execution MUST NOT occur
- S1 commitments MUST NOT be reused
- the attempt MUST be treated as failed

No partial execution is permitted.

### 22.5 Residual Risks

Residual risks include:
- delayed or failed S2 revelation
- network propagation delays
- miner inclusion variability

These risks affect availability only and MUST NOT result in unauthorized
execution.

### 22.6 Deployment Guidance

**Critical (MUST):**
- Use PQEH only with PQSEC-approved execution attempts.
- Ensure S1 commitments are non-executable under all conditions.
- Enforce single-use semantics for S1/S2 pairs.

**Recommended (SHOULD):**
- Monitor failed or delayed S2 revelations.
- Log all S1 and S2 lifecycle events for audit.
- Combine PQEH with ZEB for structured broadcast handling.

### 22.7 Non-Authority Statement

PQEH provides execution hardening only.

It does not grant authority, enforce policy, or guarantee transaction
inclusion.

---

## 23. Conformance Checklist

An implementation is PQEH conformant if it satisfies all REQUIRED items
below and documents any OPTIONAL features it claims to support.

### 23.1 Required (MUST)

☐ Implements strict S1/S2 separation with no executable artefact prior to S2  
☐ Ensures S1 commitments are non-executable under all conditions  
☐ Requires external enforcement approval (PQSEC) before S2 revelation  
☐ Enforces single-use semantics for S1/S2 pairs  
☐ Binds S2 revelation to the approved intent and session  
☐ Prevents reuse of S1 or S2 across attempts  
☐ Fails closed if S2 revelation does not occur after approval  
☐ Treats any deviation in S1/S2 ordering as failure  

### 23.2 Conditional (MUST if applicable)

☐ If used for Bitcoin execution, produces standard-valid Bitcoin transactions only at S2  
☐ If combined with ZEB, aligns execution timing with broadcast discipline  
☐ If claiming reduced quantum exposure, documents the exposure window assumptions  

### 23.3 Recommended (SHOULD)

☐ Logs all S1 and S2 lifecycle events for audit  
☐ Monitors delayed or failed S2 revelations  
☐ Tests enforcement-to-execution timing under adverse network conditions  

### 23.4 Optional (MAY)

☐ Implements metrics for S1/S2 latency  
☐ Supports alternative commitment encodings for S1  
☐ Provides tooling to visualize execution phases  

### 23.5 Testing

☐ Demonstrates that S1 artefacts cannot be broadcast or executed  
☐ Demonstrates refusal when PQSEC approval is missing or invalid  
☐ Demonstrates single-use enforcement for S1/S2  
☐ Demonstrates correct failure on delayed or missing S2  

### 23.6 Documentation

☐ Documents S1/S2 construction and lifecycle  
☐ Documents interaction with PQSEC and ZEB  
☐ Provides a conformance statement with version numbers  

---

## Annexes (Non-Normative)

### Annex A – S1/S2 Pattern Implementation (Complete)

```python
import os
import hashlib

class S1S2Manager:
    """
    Manages S1/S2 revelation pattern.
    """
    def __init__(self):
        self.active_s1 = {}
        self.used_s1 = set()
    
    def generate_s1(self, attempt_id: str) -> bytes:
        """
        Generate S1 for transaction attempt.
        """
        # Generate high-entropy S1
        S1 = os.urandom(32)  # 256 bits
        
        # Store S1 (encrypted at rest in production)
        self.active_s1[attempt_id] = S1
        
        return S1
    
    def compute_s2(self, S1: bytes) -> bytes:
        """
        Compute S2 from S1.
        """
        return hashlib.sha256(S1).digest()
    
    def reveal_s1(
        self,
        attempt_id: str,
        enforcement_outcome: dict
    ) -> tuple[bool, bytes | None]:
        """
        Reveal S1 after authorization.
        """
        # 1. Verify enforcement outcome
        if enforcement_outcome["decision"] != "ALLOW":
            return False, None
        
        # 2. Check attempt_id exists
        if attempt_id not in self.active_s1:
            return False, None
        
        # 3. Check not already used
        if attempt_id in self.used_s1:
            return False, None
        
        # 4. Retrieve S1
        S1 = self.active_s1[attempt_id]
        
        # 5. Mark as used (single-use)
        self.used_s1.add(attempt_id)
        
        # 6. Remove from active (optional: may retain for audit)
        del self.active_s1[attempt_id]
        
        return True, S1
    
    def construct_script_with_s2(
        self,
        S2: bytes,
        pubkey: bytes
    ) -> bytes:
        """
        Construct script with S2 commitment.
        """
        # OP_SHA256 <S2> OP_EQUALVERIFY <pubkey> OP_CHECKSIG
        script = bytearray()
        script.append(0xa8)  # OP_SHA256
        script.append(len(S2))
        script.extend(S2)
        script.append(0x88)  # OP_EQUALVERIFY
        script.append(len(pubkey))
        script.extend(pubkey)
        script.append(0xac)  # OP_CHECKSIG
        
        return bytes(script)
```

---

### Annex B – Transaction Construction with S1 Revelation

```python
from typing import Optional
import time

class QuantumHardenedExecutor:
    """
    Executes Bitcoin transactions with quantum hardening.
    """
    def __init__(self, s1_manager: S1S2Manager):
        self.s1_manager = s1_manager
        self.execution_traces = {}
    
    def execute_transaction(
        self,
        psbt_template: dict,
        enforcement_outcome: dict,
        custody_signers: list,
        current_tick: int
    ) -> tuple[bool, Optional[str]]:
        """
        Execute quantum-hardened transaction.
        Returns (success, txid).
        """
        import uuid
        
        # Generate attempt_id
        attempt_id = str(uuid.uuid4())
        
        # Create execution trace
        trace = {
            "trace_id": attempt_id,
            "attempt_id": attempt_id,
            "enforcement_outcome_id": enforcement_outcome["decision_id"],
            "steps": [],
            "status": "IN_PROGRESS",
            "issued_tick": current_tick
        }
        
        # STEP 1: Verify authorization
        step_start = time.time()
        
        if enforcement_outcome["decision"] != "ALLOW":
            trace["steps"].append({
                "step": "authorization",
                "timestamp_tick": current_tick,
                "duration_ms": 0,
                "status": "FAILURE",
                "error_code": "E_AUTHORIZATION_DENIED"
            })
            trace["status"] = "ABORTED"
            self.record_trace(trace)
            return False, None
        
        trace["steps"].append({
            "step": "authorization",
            "timestamp_tick": current_tick,
            "duration_ms": (time.time() - step_start) * 1000,
            "status": "SUCCESS",
            "error_code": None
        })
        
        # STEP 2: Reveal S1
        step_start = time.time()
        
        success, S1 = self.s1_manager.reveal_s1(attempt_id, enforcement_outcome)
        
        if not success:
            trace["steps"].append({
                "step": "s1_revelation",
                "timestamp_tick": current_tick,
                "duration_ms": (time.time() - step_start) * 1000,
                "status": "FAILURE",
                "error_code": "E_EXECUTION_S1_REVELATION_FAILED"
            })
            trace["status"] = "ABORTED"
            self.record_trace(trace)
            return False, None
        
        trace["steps"].append({
            "step": "s1_revelation",
            "timestamp_tick": current_tick,
            "duration_ms": (time.time() - step_start) * 1000,
            "status": "SUCCESS",
            "error_code": None
        })
        
        # STEP 3: Construct transaction with S1
        step_start = time.time()
        
        try:
            final_tx = self.construct_transaction_with_s1(psbt_template, S1)
        except Exception as e:
            trace["steps"].append({
                "step": "construction",
                "timestamp_tick": current_tick,
                "duration_ms": (time.time() - step_start) * 1000,
                "status": "FAILURE",
                "error_code": "E_EXECUTION_CONSTRUCTION_FAILED"
            })
            trace["status"] = "FAILED"
            self.record_trace(trace)
            return False, None
        
        trace["steps"].append({
            "step": "construction",
            "timestamp_tick": current_tick,
            "duration_ms": (time.time() - step_start) * 1000,
            "status": "SUCCESS",
            "error_code": None
        })
        
        # STEP 4: Collect custody signatures
        step_start = time.time()
        
        try:
            signed_tx = self.collect_signatures(final_tx, custody_signers, enforcement_outcome)
        except Exception as e:
            trace["steps"].append({
                "step": "signing",
                "timestamp_tick": current_tick,
                "duration_ms": (time.time() - step_start) * 1000,
                "status": "FAILURE",
                "error_code": "E_QUORUM_INSUFFICIENT"
            })
            trace["status"] = "FAILED"
            self.record_trace(trace)
            return False, None
        
        trace["steps"].append({
            "step": "signing",
            "timestamp_tick": current_tick,
            "duration_ms": (time.time() - step_start) * 1000,
            "status": "SUCCESS",
            "error_code": None
        })
        
        # STEP 5: Broadcast via ZEB
        step_start = time.time()
        
        try:
            txid = self.broadcast_transaction(signed_tx)
        except Exception as e:
            trace["steps"].append({
                "step": "broadcast",
                "timestamp_tick": current_tick,
                "duration_ms": (time.time() - step_start) * 1000,
                "status": "FAILURE",
                "error_code": "E_BROADCAST_FAILED"
            })
            trace["status"] = "FAILED"
            self.record_trace(trace)
            return False, None
        
        trace["steps"].append({
            "step": "broadcast",
            "timestamp_tick": current_tick,
            "duration_ms": (time.time() - step_start) * 1000,
            "status": "SUCCESS",
            "error_code": None
        })
        
        # Success
        trace["final_txid"] = txid
        trace["status"] = "COMPLETED"
        self.record_trace(trace)
        
        return True, txid
    
    def construct_transaction_with_s1(
        self,
        psbt_template: dict,
        S1: bytes
    ) -> dict:
        """
        Construct final transaction with S1 in witness.
        """
        # Clone template
        tx = psbt_template.copy()
        
        # Add S1 to witness
        for input_index, tx_input in enumerate(tx["inputs"]):
            witness = tx_input.get("witness", [])
            # Add S1 as first witness element (script-dependent)
            witness.insert(0, S1)
            tx_input["witness"] = witness
        
        return tx
    
    def collect_signatures(
        self,
        tx: dict,
        signers: list,
        enforcement_outcome: dict
    ) -> dict:
        """
        Collect M-of-N custody signatures.
        """
        # This would integrate with PQHD custody signing
        # Simplified for illustration
        
        signatures = []
        for signer in signers:
            sig = signer.sign_transaction(tx, enforcement_outcome)
            if sig:
                signatures.append(sig)
        
        # Add signatures to transaction
        for input_index, tx_input in enumerate(tx["inputs"]):
            tx_input["signatures"] = signatures
        
        return tx
    
    def broadcast_transaction(self, tx: dict) -> str:
        """
        Broadcast transaction via ZEB.
        """
        # This would integrate with ZEB
        # Simplified for illustration
        
        tx_hex = serialize_transaction(tx)
        txid = compute_txid(tx)
        
        # Broadcast via ZEB
        zeb_broadcast(tx_hex)
        
        return txid
    
    def record_trace(self, trace: dict):
        """
        Record execution trace in custody ledger.
        """
        self.execution_traces[trace["trace_id"]] = trace
        
        # In production, would write to persistent ledger
        print(f"Execution trace recorded: {trace['trace_id']} - {trace['status']}")
```

---

### Annex C – Taproot Script Construction

```python
import hashlib

def construct_taproot_output(
    internal_pubkey: bytes,
    S2: bytes,
    custody_pubkey: bytes
) -> bytes:
    """
    Construct Taproot output with quantum hardening.
    """
    # Build script with S2 commitment
    script = build_s1_s2_script(S2, custody_pubkey)
    
    # Compute script hash
    script_hash = hashlib.sha256(script).digest()
    
    # Compute taproot tweak
    tweak = compute_taproot_tweak(internal_pubkey, script_hash)
    
    # Tweak internal key
    tweaked_pubkey = tweak_pubkey(internal_pubkey, tweak)
    
    # Build output script: OP_1 <tweaked_pubkey>
    output_script = bytearray()
    output_script.append(0x51)  # OP_1 (Taproot version)
    output_script.append(32)    # 32 bytes
    output_script.extend(tweaked_pubkey)
    
    return bytes(output_script)

def build_s1_s2_script(S2: bytes, pubkey: bytes) -> bytes:
    """
    Build script: OP_SHA256 <S2> OP_EQUALVERIFY <pubkey> OP_CHECKSIG
    """
    script = bytearray()
    script.append(0xa8)  # OP_SHA256
    script.append(len(S2))
    script.extend(S2)
    script.append(0x88)  # OP_EQUALVERIFY
    script.append(len(pubkey))
    script.extend(pubkey)
    script.append(0xac)  # OP_CHECKSIG
    
    return bytes(script)

def compute_taproot_tweak(internal_key: bytes, script_hash: bytes) -> bytes:
    """
    Compute Taproot tweak: tagged_hash("TapTweak", internal_key || script_hash)
    """
    tag = b"TapTweak"
    tag_hash = hashlib.sha256(tag).digest()
    
    # Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
    data = tag_hash + tag_hash + internal_key + script_hash
    return hashlib.sha256(data).digest()

def construct_taproot_witness(
    S1: bytes,
    signature: bytes,
    script: bytes,
    control_block: bytes
) -> list:
    """
    Construct Taproot script path witness.
    """
    witness = [
        signature,       # Signature over transaction
        S1,              # Reveals S1 (satisfies OP_SHA256 check)
        script,          # Script being executed
        control_block   # Taproot control block (proves script is in tree)
    ]
    
    return witness
```

---

### Annex D – Execution Timing Analysis

```python
class ExecutionTimer:
    """
    Analyzes execution timing for quantum exposure window.
    """
    def __init__(self):
        self.timing_data = []
    
    def analyze_execution(self, trace: dict) -> dict:
        """
        Analyze execution timing from trace.
        """
        steps = trace["steps"]
        
        # Extract timing for each step
        step_timings = {step["step"]: step["duration_ms"] for step in steps}
        
        # Compute S1 exposure window
        s1_revelation_time = step_timings.get("s1_revelation", 0)
        construction_time = step_timings.get("construction", 0)
        signing_time = step_timings.get("signing", 0)
        broadcast_time = step_timings.get("broadcast", 0)
        
        # Exposure window: S1 revelation to broadcast complete
        exposure_window_ms = construction_time + signing_time + broadcast_time
        
        # Total execution time
        total_time_ms = sum(step_timings.values())
        
        analysis = {
            "trace_id": trace["trace_id"],
            "total_time_ms": total_time_ms,
            "exposure_window_ms": exposure_window_ms,
            "step_timings": step_timings,
            "exposure_ratio": exposure_window_ms / total_time_ms if total_time_ms > 0 else 0,
            "within_target": exposure_window_ms < 1000  # Target: < 1 second
        }
        
        self.timing_data.append(analysis)
        
        return analysis
    
    def get_statistics(self) -> dict:
        """
        Get timing statistics across all executions.
        """
        if not self.timing_data:
            return {}
        
        exposure_windows = [d["exposure_window_ms"] for d in self.timing_data]
        total_times = [d["total_time_ms"] for d in self.timing_data]
        
        return {
            "total_executions": len(self.timing_data),
            "avg_exposure_window_ms": sum(exposure_windows) / len(exposure_windows),
            "max_exposure_window_ms": max(exposure_windows),
            "min_exposure_window_ms": min(exposure_windows),
            "avg_total_time_ms": sum(total_times) / len(total_times),
            "within_target_count": sum(1 for d in self.timing_data if d["within_target"]),
            "within_target_percentage": sum(1 for d in self.timing_data if d["within_target"]) / len(self.timing_data) * 100
        }
```

---

### Annex E – Testing Scenarios

```python
def test_s1_s2_revelation_pattern():
    """Test S1/S2 revelation pattern."""
    mgr = S1S2Manager()
    
    # Generate S1
    attempt_id = "attempt_001"
    S1 = mgr.generate_s1(attempt_id)
    
    assert len(S1) == 32  # 256 bits
    
    # Compute S2
    S2 = mgr.compute_s2(S1)
    
    # Verify SHA256(S1) == S2
    import hashlib
    computed_s2 = hashlib.sha256(S1).digest()
    assert S2 == computed_s2
    
    # Reveal S1 with authorization
    enforcement_outcome = {"decision": "ALLOW"}
    success, revealed_s1 = mgr.reveal_s1(attempt_id, enforcement_outcome)
    
    assert success
    assert revealed_s1 == S1
    
    # Attempt replay - should fail
    success2, _ = mgr.reveal_s1(attempt_id, enforcement_outcome)
    assert not success2

def test_quantum_hardened_execution_flow():
    """Test complete quantum-hardened execution flow."""
    s1_mgr = S1S2Manager()
    executor = QuantumHardenedExecutor(s1_mgr)
    
    # Generate S1
    attempt_id = "attempt_002"
    S1 = s1_mgr.generate_s1(attempt_id)
    S2 = s1_mgr.compute_s2(S1)
    
    # Create PSBT template with S2
    psbt = create_test_psbt_with_s2(S2)
    
    # Get authorization
    enforcement_outcome = {
        "decision": "ALLOW",
        "decision_id": "decision_001"
    }
    
    # Execute
    custody_signers = get_test_signers()
    success, txid = executor.execute_transaction(
        psbt,
        enforcement_outcome,
        custody_signers,
        current_tick=1000000
    )
    
    assert success
    assert txid is not None

def test_execution_abort_on_authorization_failure():
    """Test execution aborts when authorization fails."""
    s1_mgr = S1S2Manager()
    executor = QuantumHardenedExecutor(s1_mgr)
    
    attempt_id = "attempt_003"
    S1 = s1_mgr.generate_s1(attempt_id)
    S2 = s1_mgr.compute_s2(S1)
    
    psbt = create_test_psbt_with_s2(S2)
    
    # Authorization denied
    enforcement_outcome = {
        "decision": "DENY",
        "decision_id": "decision_002",
        "error_code": "E_POLICY_CONSTRAINT_FAILED"
    }
    
    success, txid = executor.execute_transaction(
        psbt,
        enforcement_outcome,
        [],
        current_tick=1000000
    )
    
    assert not success
    assert txid is None
    
    # Verify S1 was not revealed
    assert attempt_id in s1_mgr.active_s1

def test_exposure_window_timing():
    """Test that S1 exposure window is minimal."""
    timer = ExecutionTimer()
    
    # Simulate execution with measured timing
    trace = {
        "trace_id": "trace_001",
        "steps": [
            {"step": "authorization", "duration_ms": 100},
            {"step": "s1_revelation", "duration_ms": 10},
            {"step": "construction", "duration_ms": 200},
            {"step": "signing", "duration_ms": 500},
            {"step": "broadcast", "duration_ms": 150}
        ]
    }
    
    analysis = timer.analyze_execution(trace)
    
    # Exposure window: construction + signing + broadcast
    assert analysis["exposure_window_ms"] == 850
    
    # Check within target (< 1000ms)
    assert analysis["within_target"]

def test_taproot_script_construction():
    """Test Taproot output construction with S2."""
    internal_key = os.urandom(32)
    S2 = os.urandom(32)
    custody_key = os.urandom(33)  # Compressed pubkey
    
    output = construct_taproot_output(internal_key, S2, custody_key)
    
    # Verify output format
    assert output[0] == 0x51  # OP_1
    assert output[1] == 32    # 32 bytes
    assert len(output) == 34  # OP_1 + length + 32-byte pubkey

def test_script_template_validation():
    """Test script template validation."""
    S2 = os.urandom(32)
    pubkey = os.urandom(33)
    
    # Build script
    script = build_s1_s2_script(S2, pubkey)
    
    # Verify opcodes
    assert script[0] == 0xa8  # OP_SHA256
    assert script[1] == 32    # S2 length
    assert script[34] == 0x88  # OP_EQUALVERIFY
    assert script[35] == 33    # pubkey length
    assert script[69] == 0xac  # OP_CHECKSIG
```

---

### Annex F – Deployment Checklist

**Pre-Deployment:**
* ☐ S1 generation using CSPRNG verified
* ☐ S2 derivation tested (SHA256 correctness)
* ☐ Script templates validated against Bitcoin Core
* ☐ Taproot output construction tested
* ☐ Custody signing integration verified (PQHD)
* ☐ PQSEC authorization integration tested
* ☐ ZEB broadcast integration verified
* ☐ Execution traces logging configured
* ☐ S1 secure storage implemented (encrypted at rest)
* ☐ Exposure window timing measured (target < 1s)

**Operational:**
* ☐ S1 revelation only after PQSEC authorization
* ☐ Atomic broadcast after S1 revelation
* ☐ Execution traces recorded for all attempts
* ☐ Failed attempts logged and analyzed
* ☐ S1 reuse prevention enforced
* ☐ Quorum requirements met for all executions

**Security:**
* ☐ S1 never revealed before authorization
* ☐ S1 single-use enforced
* ☐ Script templates match canonical forms
* ☐ Taproot outputs use correct commitments
* ☐ Malleability mitigations applied
* ☐ Deterministic ordering enforced
* ☐ Abort semantics tested
* ☐ No persistent state on failure

---

### Annex G – Performance Targets

```
Target Performance (p95):

Authorization:           < 500ms  (PQSEC evaluation)
S1 Revelation:          < 10ms   (Memory/decryption)
Transaction Construction: < 200ms  (PSBT finalization)
Custody Signing:        < 500ms  (M-of-N collection)
Broadcast:              < 150ms  (ZEB transmission)

Total End-to-End:       < 1400ms
S1 Exposure Window:     < 850ms  (construction + signing + broadcast)

Critical Requirement: Exposure window MUST be < 1 second for quantum resistance claims.
```

---

### Annex H – Threat Model Summary

**Adversary Capabilities:**

**TL0 (Classical):**
* Cannot break ECDSA
* Cannot derive private keys from public keys
* PQEH provides standard security

**TL1 (Pre-Quantum-Ready):**
* Preparing for quantum capability
* May attempt pre-construction
* **PQEH mitigates via S1/S2 pattern**

**TL2 (Post-CRQC):**
* Has Cryptographically Relevant Quantum Computer
* Can break ECDSA in real-time
* **PQEH cannot fully defend** (exposure window exists)
* Requires protocol-level post-quantum cryptography

**PQEH Defense Effectiveness:**

| Threat Level | Pre-Construction | Real-Time Attack | PQEH Effective? |
|--------------|------------------|------------------|------------------|
| TL0          | Not possible     | Not possible     | Yes            |
| TL1          | Prevented        | Not possible     | Yes            |
| TL2          | Prevented        | Possible (brief) | Partial       |

---

### Annex I – Frequently Asked Questions

**Q: Why doesn't PQEH provide full quantum immunity?**
A: Bitcoin itself is not quantum-immune. PQEH provides "denial of pre-construction" which prevents quantum adversaries from building transactions before authorization, but cannot prevent real-time attacks once S1 is revealed. Full quantum immunity requires protocol-level changes to Bitcoin.

**Q: What is the S1 exposure window?**
A: The time between S1 revelation and transaction broadcast. During this window, a quantum adversary with real-time capability could theoretically derive keys. PQEH minimizes this to < 1 second.

**Q: Can S1 be reused across transactions?**
A: No. S1 MUST be unique per transaction attempt and MUST NOT be reused.

**Q: What happens if broadcast fails after S1 revelation?**
A: The transaction MAY be retried via alternate channels. If all retry attempts fail, S1 MUST be discarded and a new transaction created with new S1.

**Q: Is PQEH compatible with Lightning Network?**
A: PQEH patterns can be adapted for Lightning commitment transactions, but require careful consideration of pre-signed states and penalty transactions.

**Q: What if PQSEC authorization expires during execution?**
A: Execution MUST abort immediately. EnforcementOutcome expiry is checked at each step.

---

Changelog
Version 2.1.1 (Current)
Renaming: Formally renamed from QH-EP (Quantum-Hardened Execution Patterns) to PQEH for ecosystem consistency.

S1/S2 Revelation Pattern: Standardized the separation of commitment (non-executable S1) from execution revelation (S2) to minimize the quantum attack window.

Contextual Binding: Added the Execution-Context Commitment (H_ctx) to the script-path to bind spends to specific execution environments or sessions.

Dual Recovery Model: Formalized recovery paths for both unmined timeout returns and post-confirmation fallback mechanisms.

Limitation Acknowledgment: Explicitly defined the scope as "execution-layer hardening" for current Bitcoin consensus, independent of future on-chain PQ signature upgrades.

---

## 24. Acknowledgements

This specification reflects research and iteration informed by the Bitcoin protocol and cryptography community.

PQEH implements the S1/S2 (spend-time secret) execution hardening pattern, which addresses a complementary threat surface to BIP-360. Where BIP-360 reduces long-range, at-rest public key exposure by removing the Taproot key path, PQEH reduces short-range execution-window exposure by denying pre-construction of valid spends prior to broadcast.

The author acknowledges **Ethan Heilman**, **Hunter Beast**, and **Isabel Foxen Duke**, whose work on BIP-360 and its execution-layer hardening patterns informed the S1/S2 revelation design. The clear separation between at-rest protection and execution-time hardening in their work helped establish PQEH's scope.

PQEH's design is informed by foundational Bitcoin protocol research and engineering, including:

* **Satoshi Nakamoto** — for the original design of Bitcoin and its trust-minimised consensus model.
* **Pieter Wuille** — for BIP 340, BIP 341, and BIP 342 (Schnorr, Taproot, Tapscript), enabling the script-path constructions PQEH relies upon.
* **Greg Maxwell** — for adversarial analysis, cryptographic conservatism, and transaction malleability research.
* **Andrew Poelstra** — for formal reasoning about Bitcoin script and spend policy composability.
* **The NIST Post-Quantum Cryptography Project** — for standardising post-quantum primitives that inform long-term cryptographic planning.

The S1/S2 revelation pattern draws from:

* **Lightning Network developers** — for pre-image reveal patterns in payment channels.
* **Atomic swap protocol designers** — for cross-chain commitment and revelation mechanics.
* **HTLC designers** — for hash-locked execution gating.
* **Transaction malleability researchers** — for BIP 62, BIP 66, and SegWit, which enabled reliable transaction identification.

PQEH does **not** introduce post-quantum signature schemes into Bitcoin. It provides execution-layer hardening that reduces the quantum attack window from signing-to-confirmation to broadcast-to-confirmation, within current Bitcoin consensus constraints.

Any errors, omissions, or remaining ambiguities are the responsibility of the author.

---

If you find this work useful and want to support continued development:

**Bitcoin:**  
bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw
