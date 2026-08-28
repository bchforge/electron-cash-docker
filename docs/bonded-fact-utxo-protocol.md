# Bonded Fact UTXO Protocol and Proof-of-Concept Plan

Status: exploratory protocol specification. This document refines the economic-node/harvester architecture into a falsifiable protocol for bonded, single-use computational facts, fraud challenges, pay-on-consumption, composition, and incentivized cleanup. It does **not** claim to solve stable money, does not authorize production deployment, and is not part of the current Electron Cash Docker release roadmap.

## 1. Decision summary

The proposal is viable as a narrow protocol for **endogenous, deterministic, explicitly scoped calculations**:

- a producer publishes a claimed result and locks BCH as a bond;
- the claim cannot be consumed before an enforced maturity height;
- anyone may challenge it with a fact-type-specific fraud witness;
- a successful challenge confiscates the bond and enforces a real penalty;
- a correct matured fact can be consumed once, paying the producer a usage fee and returning the bond;
- an unused fact can become cleanup-eligible, allowing any sweeper to remove it while returning nearly all of the bond to the producer;
- multiple single-use facts may be consumed to produce a higher-level fact.

The proposal is **not** currently viable as any of the following:

- a universal truth oracle;
- a proof that a supplied list contains all relevant BCH UTXOs;
- a reusable on-chain data object that unlimited transactions can inspect without consuming;
- a mechanism that automatically creates monetary stability;
- a trustless statement about an external event unless a separate verifiable or adjudicated source of truth exists.

The first proof of concept must remain inside the viable subset.

## 2. Core distinction: claims, proofs, and facts

Use three terms precisely.

### Candidate claim

A `CandidateFact` is a bonded assertion that has not yet passed its maturity period.

It is not safe for protocol-critical consumption.

### Matured fact

A candidate becomes economically acceptable after its maturity height if no challenger has spent it with a valid fraud witness.

This is optimistic security: correctness depends on at least one honest and sufficiently incentivized watcher checking the claim before use.

### Proven fact

A `ProvenFact` is a result whose correctness is checked directly by the spending transaction or by the contracts of the consumed inputs.

A proven fact does not need optimistic slashing for correctness, although it may still carry lifecycle value and cleanup incentives.

The protocol should prefer direct proof whenever it is cheap enough. Optimistic claims are justified only where full validation is expensive but a sound fraud proof is bounded and inexpensive.

## 3. Roles

### Producer

Computes a result off-chain and creates a bonded candidate claim.

The producer chooses:

- the supported fact type and version;
- the explicit input commitment;
- the claimed result;
- a producer refund public-key hash;
- an offered usage price;
- a maturity height;
- a cleanup-eligibility height;
- a bond satisfying the chosen security class.

### Watcher / challenger

Recomputes candidate claims off-chain.

If a claim is false, the watcher constructs a fraud transaction containing a contract-verifiable witness. A valid challenge consumes the candidate and pays the challenger from the bond.

### Consumer

Consumes a matured fact, pays the producer's usage price, and uses the result in the same atomic transaction.

A consumer must reject:

- unsupported fact types or versions;
- claims below the required security class;
- claims that have not reached maturity;
- stale claims according to the consumer's protocol policy;
- malformed or ambiguous serialization.

### Aggregator

Consumes multiple matured or proven facts, pays their producers, computes a higher-level result, and creates a new bonded claim or directly proven aggregate.

### Sweeper

Consumes an unused cleanup-eligible fact.

The sweep transaction:

- sends the fixed producer refund to the producer;
- pays a small fixed cleanup bounty to the sweeper;
- pays the network fee;
- leaves no successor UTXO for the cleaned fact.

### Harvester / economic node

May perform any combination of:

- indexing supported contracts;
- recomputing claims;
- challenging false claims;
- consuming useful facts;
- aggregating facts;
- sweeping cleanup-eligible facts;
- accounting for realized rewards and costs.

Electron Cash integration, if later authorized, remains an optional plugin. Electron Cash Docker is only an always-on runtime.

## 4. Current BCH constraints that shape the protocol

### 4.1 P2S and discoverability

The May 2026 BCH upgrade activated Pay to Script, bounded loops, reusable functions, and bitwise operations. P2S allows supported bare locking scripts to remain visible in the UTXO set, and BCHN 29.x exposes bytecode patterns/fingerprints through relevant RPC responses.

This is useful for permissionless discovery, but the proof of concept must measure the exact compiled byte size. P2S has a tighter standard locking-bytecode budget than P2SH32 plus unlocking bytecode.

Implementation rule:

1. prefer a directly discoverable P2S encoding if the complete contract and parameters fit standard policy and current tooling;
2. otherwise use P2SH32 for the first contract proof and publish deterministic discovery metadata without creating a permanent metadata UTXO;
3. do not claim P2S compatibility until an actual standard transaction is accepted by the target node/network.

### 4.2 Inputs are consumed

Current BCH transactions do not provide generally available read-only inputs.

A fact inspected as an ordinary input is consumed. Therefore V0.1 facts are deliberately **single-use**.

A consumer may create a successor fact, but this creates a sequential state thread and potential contention. Unlimited concurrent reuse is outside V0.1.

Read-only inputs are a proposed future capability and must not be assumed by this implementation.

### 4.3 No global UTXO-set completeness proof

CashVM cannot currently verify that a supplied list is exactly the complete set of all matching UTXOs at a block height.

Therefore V0.1 facts may only claim results over:

- an explicit byte commitment supplied as part of the fact;
- a bounded dataset with a canonical serialization;
- authenticated input facts consumed by the same transaction;
- a protocol-owned state commitment whose complete transition is enforced by its covenants.

V0.1 must not claim:

> This result includes every current protocol UTXO.

A later protocol-state tree may make such a statement possible for the protocol's own state, but it is not part of the first proof of concept.

### 4.4 Transactions do not execute automatically

A block height can make a spending branch valid, but it does not broadcast the transaction.

All lifecycle transitions require someone to construct and broadcast a spend.

"Automatic refund" therefore means:

> any sweeper can execute a transaction that deterministically refunds the producer without requiring the producer to be online.

### 4.5 Lower timelocks are enforceable; hard upper expiry is not assumed

The contract can enforce "not before height/time X" using transaction locktime/sequence rules.

The first specification must not pretend that a transaction can reliably prove it is being mined before a hard upper deadline merely because its chosen `nLockTime` is below that deadline.

Therefore:

- `maturity_height` means the earliest height at which consumption is allowed;
- `sweep_height` means the earliest height at which cleanup is allowed;
- a challenge remains valid whenever the candidate UTXO still exists and the fraud witness is valid;
- after `sweep_height`, consumption and cleanup may race until one spend confirms;
- off-chain consumers must enforce freshness policy;
- a protocol requiring hard on-chain freshness must use an authenticated epoch/state transition, not a naive upper timestamp.

## 5. V0.1 object model

A candidate fact conceptually commits to:

```text
protocol_id
protocol_version
fact_type_id
fact_type_version
subject_id
input_commitment
claimed_result
producer_pkh
maturity_height
sweep_height
usage_fee_sats
cleanup_bounty_sats
minimum_slash_fee_sats
security_class
serialization_id
```

The actual encoding must be compact, canonical, and independently reproduced by two implementations.

### Required invariants

- `maturity_height < sweep_height`;
- `usage_fee_sats >= 0`;
- `cleanup_bounty_sats > 0`;
- `minimum_slash_fee_sats > 0`;
- contract value covers all required payouts and fees;
- no payout is below current standard dust policy;
- unsupported versions fail closed;
- no field has multiple valid serializations;
- all arithmetic uses checked integer semantics;
- every spending branch fixes all economically relevant outputs.

## 6. Fact-type interface

Each accepted fact type is a versioned protocol, not arbitrary user-supplied code.

A fact-type specification must define:

```text
canonical_input_encoding(input) -> bytes
input_commitment(input) -> bytes32
compute(input) -> result
canonical_result_encoding(result) -> bytes
fraud_witness_format
verify_fraud(commitment, claimed_result, witness) -> bool
maximum_input_size
maximum_witness_size
maximum_result_size
security assumptions
```

A claim is slashable only if `verify_fraud` is sound:

- no witness can slash a correct claim;
- at least one bounded witness can slash every false claim in the supported domain.

If either property is not proven by tests and analysis, that fact type is not eligible for optimistic publication.

## 7. Initial proof-of-concept fact type

Implement one intentionally bounded computation first:

```text
SUM4_V1
```

Input:

```text
four fixed-width non-negative integers
```

Commitment:

```text
HASH256(domain_separator || canonical_fixed_width_values)
```

Claimed result:

```text
sum of the four integers
```

Fraud witness:

```text
the exact four committed integers
```

Challenge succeeds only if:

1. the witness re-encodes to the stored commitment;
2. the checked sum differs from the claimed result;
3. all values and the result remain inside the declared bounds.

This type is deliberately small. Its purpose is to prove:

- canonical serialization;
- off-chain computation;
- optimistic publication;
- deterministic fraud proof;
- slashing;
- maturity;
- pay-on-consumption;
- cleanup;
- indexing;
- transaction construction.

It is not presented as an economically valuable calculation by itself.

After `SUM4_V1` passes, one additional fact type may be added only if it proves protocol generality rather than expanding scope. A suitable candidate is `MAX4_V1` or another fixed-size function with a complete, bounded fraud witness.

## 8. Lifecycle and value flows

Let the candidate UTXO carry value `V`.

Conceptually:

```text
V = refundable producer bond
  + cleanup bounty budget
  + transaction-fee budget / carrier value
```

Exact values must be configurable and validated against network policy.

### 8.1 Publish

The producer creates the candidate UTXO and pays the publication transaction fee.

The producer exposes the canonical input preimage through a content-addressed off-chain channel or directly to watchers. Data availability is required: a hidden preimage makes independent checking impossible.

The contract stores only the commitment and compact result/state.

### 8.2 Challenge false claim

The challenge branch:

- accepts a fact-type-specific fraud witness;
- recomputes the commitment;
- proves the claimed result is false;
- requires the challenger to sign the transaction with the key receiving the challenge payout;
- pays the allowed challenge reward to that signed payout destination;
- enforces a minimum miner-fee penalty by limiting total challenge outputs;
- creates no successor fact.

The enforced miner-fee penalty is important. If the producer challenges their own false claim, they may recover the challenge payout but must still lose at least the minimum penalty plus transaction costs.

This prevents fully cost-free self-challenge spam without introducing a controlled treasury.

### 8.3 Consume matured fact

The consumption branch is invalid before `maturity_height`.

A valid consumer transaction must:

- pay the producer the full refundable amount plus `usage_fee_sats`;
- bind the producer output to `producer_pkh`;
- pay network fees from consumer-supplied funds or a precisely defined allowance;
- use the result in the same transaction or create a valid successor/aggregate;
- create no duplicate of the consumed fact unless the fact type explicitly defines a safe successor rule.

A false fact that remains unchallenged until maturity can still be consumed. This is the defining optimistic-security assumption. The test environment must measure watcher liveness and explicitly demonstrate this failure mode.

### 8.4 Sweep unused fact

The cleanup branch is invalid before `sweep_height`.

A valid sweep must:

- require the sweeper to sign for the cleanup-bounty destination;
- pay a fixed refund to `producer_pkh`;
- pay exactly the allowed cleanup bounty to the sweeper;
- leave a bounded fee;
- create no successor fact.

The producer may also sweep their own fact, in which case they effectively receive both outputs after signing both roles. This is acceptable.

### 8.5 Race behavior

All branches spend the same UTXO, so only one confirms.

Expected races include:

- challenge vs consume;
- challenge vs sweep;
- consume vs sweep;
- multiple challengers;
- multiple sweepers.

The confirmed spend determines the outcome. No race may allow theft of the fixed producer refund or creation of an invalid result.

## 9. Security classes and bond sizing

The protocol must not imply that every bonded fact can safely control unlimited value.

Each fact declares a `security_class` or equivalent `max_value_at_risk`.

Consumers enforce:

```text
consumer_value_at_risk <= allowed_value(fact_bond, fact_type, maturity, watcher_policy)
```

V0.1 may use a fixed conservative ratio.

The production relation must account for:

- producer bond;
- minimum irreversible/self-challenge penalty;
- challenge reward;
- number and independence of watchers;
- maturity duration;
- expected detection probability;
- maximum profit available from a false fact;
- correlated or repeated attacks.

The target economic property is:

```text
expected cost of successful false use
>
maximum expected extractable value
```

The PoC must not claim this property for production economics. It must only provide measurements and a model.

## 10. Composition of independent pieces

The protocol is intended to form a reduction DAG:

```text
Fact A ----\
            +--> Aggregate Fact D ----\
Fact B ----/                         |
                                      +--> Final consumer action
Fact C -----------------------------/
```

### V0.1 rule: single-use composition

Child facts are ordinary inputs and are consumed.

The aggregation transaction must:

- satisfy each child's maturity and payout requirements;
- pay every child producer;
- compute or enforce the aggregate result;
- lock a new bond for the parent fact if the parent remains optimistic;
- avoid silently reducing the parent security class;
- create no orphaned child successor unless required by a documented rule.

### Trustless lineage requirement

A parent may be described as an authentic aggregate only if one of these is proven:

1. the child contracts directly enforce the parent output/result in the aggregation transaction; or
2. an authenticated tracking token/state covenant enforces the transition; or
3. a complete self-contained fraud proof can prove a false parent from the parent's committed data.

An indexer's observation that the transaction "looks right" is not enough for protocol-critical authenticity.

### First aggregation experiment

After the basic fact lifecycle passes, implement a two-child sum aggregation.

The implementation must first test the smallest current-BCH method for exposing child results to all validating inputs:

- fixed-offset parsing of directly visible P2S locking bytecode; or
- authenticated CashToken NFT commitments; or
- another fully enforced current-consensus construction.

Select the smallest construction that passes actual bytecode, standardness, and transaction tests. Do not assume future read-only inputs.

If no safe construction fits the PoC budget, record aggregation as a proven current-tooling blocker while retaining the completed leaf-fact lifecycle.

## 11. Garbage collection semantics

The cleanup mechanism is a first-class protocol requirement, not an optional convenience.

Every ephemeral V0.1 object must have a path that:

- eventually becomes permissionlessly spendable;
- returns the producer's defined refund;
- pays a small executor bounty;
- leaves no replacement object;
- avoids sub-dust outputs;
- cannot redirect the producer refund;
- cannot be activated before the cleanup height.

This is **economic garbage collection**.

It does not guarantee every object is cleaned. It makes cleaning rational when:

```text
cleanup bounty > transaction cost + opportunity cost
```

The PoC must measure this inequality at multiple fee rates.

## 12. Indexing and discovery

The indexer is replaceable and non-authoritative.

It should identify candidates by:

- P2S locking-bytecode prefix/fingerprint where available;
- exact contract-template fingerprint;
- protocol/version prefix;
- canonical parameter parsing;
- optional transaction metadata for a P2SH32 PoC fallback.

Two independent indexer implementations must reconstruct the same set from the same chain fixture.

An indexer must classify at least:

```text
CANDIDATE
MATURE
CLEANUP_ELIGIBLE
SPENT_CHALLENGED
SPENT_CONSUMED
SPENT_SWEPT
UNKNOWN_VERSION
MALFORMED
```

`MATURE` and `CLEANUP_ELIGIBLE` are policy views based on chain height and object state; they are not new consensus states.

## 13. Electron Cash plugin boundary

The first on-chain PoC should use a standalone command-line watcher/harvester.

Only after contract and transaction behavior passes should an Electron Cash plugin prototype be attempted.

The plugin must be optional and disabled by default.

Required wallet policy controls:

- supported fact types and versions;
- watch-only mode;
- maximum BCH committed as producer bond;
- maximum BCH spent per fact consumption;
- minimum net expected reward;
- maximum fee;
- minimum maturity;
- minimum bond/security class;
- allowed payout wallet/account;
- no automatic use of unknown contract templates;
- deterministic transaction preview and audit log;
- explicit mainnet disablement during PoC.

The plugin may operate as:

- producer;
- watcher/challenger;
- consumer;
- sweeper.

Autonomous hot-wallet spending is not permitted without separately proven policy limits and an explicit later authorization.

## 14. Threat model

### False claim

Mitigation: deterministic fraud witness, producer bond, maturity delay, watchers, usage-value cap.

Residual: a false claim can be consumed if every watcher fails before use.

### Self-challenge

Mitigation: enforce a minimum transaction-fee penalty that cannot be recovered even if producer and challenger are the same entity.

### Claim spam

Mitigation: publication fee, locked bond, cleanup budget, minimum tracked bond, supported-template allowlist in clients.

### Data withholding

Mitigation: clients reject candidates whose committed preimage is unavailable. Data availability is a protocol requirement.

Residual: the chain commitment alone does not make the preimage available.

### Invalid challenge griefing

Mitigation: invalid fraud transactions fail consensus/mempool validation; the challenger pays their own construction and relay costs.

### Challenge reward theft/front-running

Mitigation: challenger signs the transaction and the contract binds payout to the signing key.

Residual: another challenger or miner may independently construct a competing valid challenge. Correct removal is more important than reward exclusivity.

### Cleanup reward theft

Mitigation: sweeper signs the transaction and payout is bound to the signing key; producer refund is fixed independently.

### Stale-fact use

Mitigation: consumer-side freshness rules, cleanup incentives, authenticated protocol epochs for future critical uses.

Residual: V0.1 does not enforce a hard on-chain upper validity deadline.

### Bond too small

Mitigation: consumer value-at-risk cap and security class.

### Global completeness lie

Mitigation: V0.1 forbids claims about complete global UTXO state.

### Reuse/concurrency

Mitigation: V0.1 is explicitly single-use. Reproduction or read-only reuse requires a later design.

### Dust and uneconomic cleanup

Mitigation: minimum object value and cleanup bounty are tested against fee scenarios; no sub-dust outputs.

### Contract/version confusion

Mitigation: domain separation, versioned canonical serialization, exact fingerprints, fail-closed clients.

## 15. Relationship to stable-money research

This protocol can provide:

- authenticated internal calculations;
- economically incentivized computation;
- fraud detection;
- aggregation of explicit state;
- permissionless execution;
- lifecycle cleanup.

It does not by itself provide:

- an external price;
- purchasing-power stability;
- a negative-feedback monetary policy;
- new collateral after a market loss;
- proof that an aggregate includes all relevant market state.

Candidate V2 and V3 negative findings remain unchanged.

A future monetary experiment may use Fact UTXOs as internal sensors only after proving:

1. the facts cover an authenticated protocol state;
2. the facts are sufficiently fresh;
3. the controller's response is economically stabilizing;
4. all required actors have sustainable incentives;
5. the system survives adversarial simulation.

Fact UTXOs are infrastructure, not evidence that stable money is solved.

## 16. Proof-of-concept delivery plan

### Phase 0 — Specification lock

Deliver:

- canonical field encoding;
- exact transaction shapes;
- exact value-flow equations;
- fact-type interface;
- `SUM4_V1` definition;
- threat model;
- acceptance configuration;
- choice of P2S or documented P2SH32 fallback.

No contract implementation begins until these are frozen.

### Phase 1 — Pure reference model

Implement a deterministic TypeScript model of:

- publish;
- valid/invalid fraud witness;
- maturity;
- consume;
- sweep;
- races;
- value conservation.

Use property-based tests and fixed seeds.

### Phase 2 — CashScript/bytecode contract

Implement the candidate contract on MockNetworkProvider or equivalent local VM tests.

Prove every branch and all invalid variants.

Measure:

- compiled byte size;
- initialized byte size;
- unlocking size;
- VM limits;
- transaction size;
- minimum standard output values;
- fee requirements.

### Phase 3 — Network PoC

Deploy only on chipnet/testnet-compatible infrastructure with non-valuable funds.

Execute real lifecycle transactions:

1. true candidate published;
2. premature consume rejected;
3. true candidate consumed after maturity;
4. false candidate published;
5. false candidate challenged and slashed;
6. self-challenge penalty demonstrated;
7. unused candidate swept after cleanup height;
8. premature sweep rejected;
9. competing sweeps/challenges tested;
10. no residual Fact UTXO remains after each terminal path.

### Phase 4 — Independent indexer and harvester

Implement a standalone CLI daemon that:

- discovers candidates;
- fetches/reconstructs committed data;
- recomputes `SUM4_V1`;
- challenges false candidates;
- consumes a selected correct fact under policy;
- sweeps eligible facts;
- records exact P&L.

Build a second minimal read-only indexer independently and compare results.

### Phase 5 — Composition experiment

Implement two-child aggregation only after the leaf lifecycle passes.

Prove authentic lineage and exact producer payouts.

Do not fake composition through off-chain trust.

### Phase 6 — Electron Cash plugin prototype

Only if Phases 0–5 pass:

- package watcher/harvester logic as an optional plugin;
- default to watch-only;
- disable mainnet autonomous spending;
- enforce wallet policy limits;
- run continuously in Electron Cash Docker testnet4/chipnet-equivalent setup where technically supported;
- prove restart recovery and no duplicate actions.

## 17. Locked proof-of-concept acceptance gates

The PoC is `SUPPORTED_FOR_FURTHER_RESEARCH` only if all applicable gates pass.

### Correctness

- every false `SUM4_V1` claim has a valid fraud witness;
- no true `SUM4_V1` claim has a valid fraud witness;
- no overflow, negative-value, or serialization ambiguity exists;
- consume before maturity is impossible;
- cleanup before sweep height is impossible;
- fixed producer refund cannot be redirected;
- challenged, consumed, and swept paths leave no successor fact;
- value accounting reconciles exactly.

### Economic lifecycle

- external challenge is profitable at the configured fee rate;
- self-challenge causes an enforced irrecoverable loss;
- cleanup is profitable at the configured fee rate;
- producer recovers the specified refund on valid consumption or cleanup;
- producer earns the exact usage fee only on consumption;
- no role relies on forced unprofitable behavior.

### Security

- unsupported versions are ignored/rejected;
- malformed candidates cannot be consumed;
- stale-fact policy is explicit;
- missing preimage is detected;
- bond/security class limits consumer value at risk;
- race tests cannot steal fixed payouts;
- reorg/restart handling does not double-act.

### Network and tooling

- actual standard transactions pass node mempool acceptance;
- P2S discoverability is proven or the P2SH32 fallback is labeled accurately;
- independent indexers agree;
- all canonical transaction IDs and raw transactions are recorded;
- no mainnet funds are used.

### Cleanup

- every ephemeral object has a reachable cleanup path;
- no test lifecycle leaves protocol dust;
- cleanup economics remain positive across the frozen fee scenarios.

## 18. Final classification

Use exactly one research result:

```text
SUPPORTED_FOR_FURTHER_RESEARCH
NOT_SUPPORTED
COMPLETE_WITH_EXTERNAL_BLOCKER
```

`SUPPORTED_FOR_FURTHER_RESEARCH` does not authorize production, a stable asset, or mainnet autonomous wallet operation.

It means only that the bounded Fact UTXO lifecycle, slashing, pay-on-use, composition target, and economic cleanup have been demonstrated with reproducible evidence.

## 19. Explicit exclusions

The first PoC does not implement:

- a stablecoin or lower-volatility asset;
- external price facts;
- human arbitration;
- a global protocol-state root;
- UTXO-set completeness proofs;
- ZK proofs;
- interactive verification games;
- read-only inputs;
- production oracle operation;
- mainnet deployment;
- a public hot-wallet harvester;
- a new BCH node implementation;
- BCH consensus or CHIP changes.

## 20. Primary references

- CashTokens specification and examples: <https://cashtokens.org/docs/spec/chip/> and <https://cashtokens.org/docs/spec/examples/>
- CashScript covenant/introspection guide: <https://cashscript.org/docs/guides/covenants>
- CashScript globals and timelock behavior: <https://cashscript.org/docs/language/globals>
- CashScript types and byte parsing: <https://cashscript.org/docs/language/types>
- P2S CHIP: <https://github.com/bitjson/bch-p2s>
- BCHN release notes for the May 2026 upgrade and bytecode-pattern RPC support: <https://github.com/bitcoin-cash-node/bitcoin-cash-node/releases>
- TXv5/read-only-input research, not assumed by V0.1: <https://bitcoincashresearch.org/t/chip-2025-01-txv5-transaction-version-5/1490>
- Anyone-can-execute and cleanup design discussion: <https://bitcoincashresearch.org/t/discussion-on-best-practices-for-building-anyone-can-spend-automata-contracts-and-covenants/916>

## 21. Current conclusion

The useful and defensible first implementation is not a general decentralized oracle.

It is:

> a bonded, single-use computational receipt with a sound bounded fraud proof, delayed consumption, producer payment on use, and self-funded cleanup.

That object is small enough to implement and falsify now. If it passes, it can become one primitive used by the future economic node and Electron Cash harvester plugin. Only later should the project test richer calculations, authenticated state aggregation, reusable facts, or monetary feedback systems.
