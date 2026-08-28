# Economic Node and Harvester Architecture Note

Status: exploratory research note. This document records a possible long-term architecture discussed around Electron Cash Docker, UTXO-native markets, harvesting/solving, distributed oracles, and a possible later monetary layer. It is **not** part of the current Electron Cash Docker release roadmap and does not authorize implementation.

## 1. Core idea

Bitcoin Cash can host economically meaningful UTXOs whose locking conditions express an executable intention, for example:

> This output contains asset X and may be spent by anyone who constructs a transaction that delivers Y under the encoded conditions.

Such outputs are already confirmed UTXOs. They are not mempool transactions waiting to be mined. They may remain unspent for an arbitrary period until someone constructs a valid transaction that satisfies their conditions.

The intended flow is:

```text
confirmed UTXO intention
        |
        v
harvester discovers an executable opportunity
        |
        v
harvester/solver constructs a satisfying transaction
        |
        v
wallet signs only the required local inputs
        |
        v
mempool
        |
        v
miner confirms transaction
```

The harvester therefore does not "mine UTXOs". It **discovers, solves, and consumes economically interesting UTXOs**. A miner still performs ordinary block inclusion.

## 2. Open market rather than owned exchange

A standardized family of intention contracts could form a permissionless market directly on BCH.

Examples include:

- BCH for CashToken offers;
- CashToken for BCH offers;
- CashToken-for-CashToken offers;
- NFT sales;
- later, loans, options, challenges, liquidations, or other positions where the required conditions can be enforced by BCH contracts.

The blockchain is the economic source of truth. An indexer reconstructs a useful view of outstanding intentions, but it does not own or authorize the market. Different indexers and frontends should be able to discover the same canonical UTXOs and independently construct valid spends.

The design target is therefore closer to an **open order/intention protocol** than to a conventional exchange with a proprietary order database.

## 3. Harvester role

A harvester continuously watches for supported intention contracts and determines whether one or more can be executed profitably or usefully.

Possible functions:

1. identify supported contract templates or protocol identifiers;
2. parse the assets and executable conditions;
3. calculate whether the local wallet can satisfy an intention;
4. find direct fills or compatible combinations;
5. construct the candidate BCH transaction;
6. expose the exact transaction and expected economics before signing;
7. request only the signatures required from the local wallet;
8. broadcast successful transactions;
9. account for realized spread/solver fee and costs.

The harvester may eventually act as:

- taker;
- solver;
- market maker;
- arbitrageur;
- challenger;
- liquidation agent.

These are economic roles, not consensus roles.

## 4. Electron Cash integration decision

If harvesting is implemented for Electron Cash, it should be implemented as an **Electron Cash plugin**, not as new behavior embedded directly into Electron Cash Docker itself.

Electron Cash Docker remains the always-on packaging/runtime environment. The plugin owns wallet-facing behavior.

Conceptually:

```text
Electron Cash Docker
        |
        +-- Electron Cash
                |
                +-- Harvester plugin (optional)
```

The plugin should be optional and disabled by default.

The Docker project may later provide a supported way to install/run the plugin, consistent with the project's plugin-distribution roadmap, but the harvester protocol and economic logic should remain independently versioned and testable rather than being coupled to container internals.

### Security boundary

The plugin must not be designed as an unrestricted autonomous hot-wallet spender.

A later implementation should define explicit limits such as:

- allowed asset/category identifiers;
- maximum BCH exposure per transaction and per time window;
- minimum expected profit/spread;
- maximum fee;
- permitted contract templates;
- explicit signing policy;
- deterministic transaction preview/logging;
- fail-closed behavior for unknown contract versions or ambiguous economics.

No such policy is specified by this research note; these are required implementation gates if the plugin is later authorized.

## 5. Economic incentive for harvesting

The architecture should not rely on altruism.

A harvester may be compensated by one or more of:

- an explicit solver fee allowed by the intention contract;
- bid/ask spread;
- arbitrage profit;
- liquidation bounty;
- challenge reward;
- protocol-defined execution reward.

Every future role must have a measurable economic incentive. A required participant that systematically loses money without another compensating utility is not a sustainable protocol role.

## 6. Future economic node

The harvester plugin is a first application. A broader future project could package several permissionless economic roles into an always-on **BCH economic node**.

This is conceptually separate from a BCH consensus/full node.

Possible components:

```text
BCH consensus/full-node access
        |
        +-- UTXO/indexing layer
        +-- intention discovery
        +-- harvester/solver
        +-- market maker/arbitrage logic
        +-- challenge/liquidation agent
        +-- oracle publisher
        +-- oracle aggregator/verifier
        +-- local API for wallets/plugins
```

An economic node answers questions such as:

- what executable economic positions currently exist?;
- which can this operator profitably consume?;
- which positions appear challengeable or liquidatable?;
- what signed observations does this operator publish?;
- what independent observations are available from other operators?

A BCH consensus node answers a different question:

> Is this transaction/block valid under BCH consensus?

These layers must not be conflated.

## 7. Oracle layer

A later economic node may also act as an independent oracle publisher.

`oracles.cash` demonstrates signed oracle messages usable by BCH applications and is relevant prior art/reference infrastructure, but a genuinely decentralized oracle layer must not create many apparent nodes that all merely repeat one operator's feed.

The desired direction is multiple independently operated publishers that each obtain observations independently and sign their own messages.

Conceptually:

```text
publisher A -> independent observations -> signed message
publisher B -> independent observations -> signed message
publisher C -> independent observations -> signed message
...
                         |
                         v
              aggregation / median / quorum
                         |
                         v
                   BCH contract use
```

Exact source selection, aggregation, stake/reputation, fault thresholds, freshness rules, and manipulation resistance remain unresolved and require a separate specification and simulation before implementation.

The oracle network should be permissionless or broadly replaceable; no single website, company, or canonical frontend should be required for protocol correctness.

## 8. Relationship to a possible stable monetary layer

Earlier endogenous-stability research in `bch-stability-lab` produced negative results for two distinct families:

- Candidate V2 achieved apparent U stability by transferring destructive losses to risk providers/system bad debt;
- Candidate V3 preserved backing/settlement but U largely inherited BCH volatility when no external reference was available.

Those results should remain intact and must not be reinterpreted as pending tuning work.

A distributed oracle layer would create a **different research family**: the protocol could use externally referenced information without depending on a single price-feed operator. This may enable overcollateralized positions, permissionless challenges/liquidations, and a genuinely reference-stabilized asset.

However, decentralizing the oracle does not remove the fact that an asset deliberately tracking USD, EUR, BCH, or another reference is still economically reference-based. Any later monetary design therefore requires a fresh economic simulation and separate legal/regulatory analysis before implementation.

The economic-node/harvester project must remain useful even if no stable monetary layer is ever deployed.

## 9. Polymarket-style human resolution

Optimistic human resolution is a possible last-resort mechanism for propositions that cannot be settled mechanically or through economically committed market actions.

General pattern:

```text
assertion + bond
      |
      +-- undisputed -> accepted
      |
      +-- disputed -> larger bond / escalation -> exceptional human resolution
```

This should **not** be the default mechanism for price discovery where bids, challenges, and auctions can express the information directly with committed capital.

For price-sensitive liquidation, a Frankencoin-style challenge/auction mechanism is generally a stronger model: participants demonstrate their valuation by actually buying/selling at the claimed price rather than merely voting on it.

Human arbitration remains an optional backstop, not a required core layer unless future research proves otherwise.

## 10. Application-level consensus vs BCH consensus

Even if nearly every wallet, plugin, harvester, or economic node implements the same intention protocol, oracle rules, or monetary layer, that does **not** automatically make those rules part of BCH consensus.

It would instead be an application/protocol standard implemented on top of BCH consensus primitives.

Conceptually:

```text
BCH consensus
    |
    +-- transactions / UTXOs / CashTokens / P2S / covenant capabilities
            |
            +-- open intention protocol
                    |
                    +-- harvesters / solvers
                    +-- economic nodes
                    +-- optional oracle protocol
                    +-- optional monetary protocols
```

If all major ecosystem software adopted a protocol, it could become a strong **de facto economic standard**, analogous to a widely adopted Internet application protocol.

It would become "like a CHIP" only in the social/adoption sense.

For it to become BCH consensus in the technical sense, a future CHIP would have to modify the rules all consensus implementations use to determine transaction or block validity. There is currently no reason to assume such a consensus change is necessary or desirable.

The preferred architecture is to use existing BCH primitives and let useful protocols gain adoption without requiring a network consensus change.

## 11. Suggested staged path

The ideas should be validated in increasing order of dependency.

### Stage A — Open intention protocol / DEX primitive

Specify the smallest interoperable on-chain intention format and prove that independent clients can:

- discover the same confirmed offers;
- validate their semantics;
- construct valid fills;
- consume them atomically;
- reconstruct the market without a canonical server.

Do not add stability or oracle requirements.

### Stage B — Electron Cash harvester plugin

Implement an optional plugin that watches supported intentions and can construct economically valid fills under explicit wallet safety limits.

Prove usefulness and sustainable solver economics.

### Stage C — Economic node

Generalize always-on roles beyond the wallet plugin:

- indexing;
- harvesting;
- arbitrage;
- challenge/liquidation;
- eventually oracle publication/verification.

This should be a separate architecture/project rather than silently expanding Electron Cash Docker's core responsibilities.

### Stage D — Distributed oracle research

Build and adversarially test an independent multi-publisher oracle network only if concrete protocols require external information.

### Stage E — Monetary-layer research

Only after the oracle layer and economic roles are independently validated, reopen reference-stability research as a new candidate family.

Do not reuse Candidate V2/V3 labels or alter their negative conclusions.

## 12. Important preserved conclusions

1. A UTXO intention is a confirmed, unspent economic object, not a mempool transaction.
2. Harvesters consume intentions; miners still mine ordinary transactions.
3. The market should be reconstructible from blockchain state by replaceable indexers/clients.
4. Electron Cash integration, if built, is an **optional plugin**.
5. Electron Cash Docker is an always-on host/runtime, not the owner of the market protocol.
6. A future economic node may combine discovery, harvesting, liquidation, and independent oracle roles.
7. Multiple nodes repeating one oracle operator are not oracle decentralization.
8. Distributed oracles can reduce operator dependence but do not erase an external reference from a reference-stabilized asset.
9. Widespread application adoption creates de facto protocol consensus, not BCH consensus.
10. A CHIP/consensus change is unnecessary unless existing BCH primitives prove insufficient for a required protocol invariant.
11. The DEX/harvester path should provide standalone utility even if stable-money research never succeeds.

## 13. Current status

This document is architectural research only.

No implementation, release assignment, network deployment, stable asset, oracle network, or consensus proposal is authorized by this note.

The next independently useful technical research target is the smallest interoperable **UTXO intention protocol + harvester** that can demonstrate an open market without a canonical operator.
