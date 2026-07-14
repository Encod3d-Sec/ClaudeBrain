---
title: "Smart Contract and Web3 Attacks"
type: technique
tags: [blockchain, web3, smart-contract, defi, solidity, evm, erc-4337, proxy, delegatecall]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-blockchain]
---

## What it is

Attacking the Web3 value chain: smart contracts and the off-chain machinery around them (signing infrastructure, proxies, oracles, bridges, automation) that can mint, price, authorize, or route value. Covers proxy takeover, account-abstraction pitfalls, and DeFi/AMM economic drains, plus the audit toolchain that catches them.

## How it works

Attack surface is broader than the contracts: inventory everything that can mint, price, authorize, or route value, on-chain and off-chain. That includes custodial signing (HSM/KMS, signing bots), proxy-admin/governance/timelock/pause keys, oracles and price feeds, market-making and CI/CD automation that can request signatures, and bridges/relayers. Each is an attack candidate, not just the Solidity.

Core mechanics worth encoding: EVM transactions derive the sender from the signature; gas is priced in gwei with base fee + tip. Uniswap-v4-style pools attach hook contracts (a non-zero `PoolKey.hooks`) that the PoolManager calls before/after swap and liquidity ops and that can return custom balance deltas. Flash loans (Aave/Balancer) supply transient capital inside one transaction, financing most economic attacks without long-lived funds.

## Attack phases
Exploitation (Web3 audit, DeFi red-team, on-chain PoC on forked mainnet).

## Prerequisites
- Contract source or verified bytecode, the deployment (proxy/impl addresses, storage layout), and a forked-mainnet environment for PoC.
- For signing-workflow attacks, access to or influence over the proposal/signing UI path.

## Methodology

### Delegatecall proxy takeover via slot-0 collision and signing-workflow compromise

The Bybit/Safe 2025 pattern, high-impact and reusable. Safe proxies store `masterCopy` (the implementation pointer) at storage slot 0 and support `operation = 1` (delegatecall). A signed `execTransaction` that delegatecalls an attacker contract runs that code in the proxy's storage context; a function that looks like ERC-20 `transfer(address,uint256)` but writes its argument into slot 0 silently repoints the proxy to attacker logic = full wallet takeover.
```solidity
// attacker contract: mimics transfer() but overwrites slot 0 (masterCopy)
uint256 stor0;                              // slot 0
function transfer(address _to, uint256) external { stor0 = uint256(uint160(_to)); }
// victims sign: execTransaction(..., to=attacker, data=transfer(newImpl,0), operation=1)
```
The other half is a supply-chain compromise of the signing UI: injected JS mutates the EIP-712 payload (`to`, `data`, `operation`, gas) immediately before `signTransaction`, then restores the original UI so co-signers see a benign proposal while the signature commits to the attacker payload (blind-signed because wallets show structured data but do not decode nested calldata or highlight `operation=delegatecall`). Defenses: gateway must recompute `safeTxHash` and reject proposals whose hash/signature do not match the submitted fields; hardware EIP-712 clear-signing; a Safe Guard vetoing delegatecall (Safe >= v1.3.0); keep upgrade pointers off slot 0.

### ERC-4337 / account-abstraction pitfalls

Account abstraction validates every UserOperation in a bundle before executing any of them; that ordering creates the bugs:
- Direct-call bypass: any `execute`/fund-moving function not restricted to the `EntryPoint` (or `msg.sender == address(this)` for self-admin) is called directly to drain the account.
- Unsigned gas fields: if the signature covers only `callData` and not `preVerificationGas`/`verificationGasLimit`/`callGasLimit`/`maxFeePerGas`/`maxPriorityFeePerGas`, a bundler inflates fees and drains ETH. Sign over the EntryPoint `userOpHash` (it binds the gas fields).
- Stateful-validation clobbering: writing validation results to storage is unsafe because another op in the same bundle overwrites it before your execution runs. Keep `validateUserOp` stateless.
- ERC-1271 replay: `isValidSignature` must bind to this contract and chain via EIP-712 domain (`verifyingContract`+`chainId`) and return the magic `0x1626ba7e`; a raw-hash recover replays across accounts/chains.
- Fee drain by revert-after-validation: once validation succeeds fees are committed even if execution reverts; paymasters paying in validation and charging in a revertable `postOp` leak funds.
- Counterfactual/`initCode` deployment: bind salt/owner/validator to signed intent, use CREATE2 deterministically, make init one-shot, else a frontrunner burns the counterfactual address. Same one-shot self-call rule for ERC-7702 EOA init.
- Bundler-rejected validation: no `TIMESTAMP`/`NUMBER`/`BLOCKHASH`, no `SSTORE`, no unbounded loops or external oracle reads inside validation, bundlers simulate and drop it.

### DeFi/AMM economic exploitation

Two economic-drain archetypes:

Rounding/precision drift in custom AMM hooks (Bunni V2): a hook doing extra fixed-point accounting per swap can round inconsistently across a threshold/tick boundary so residue credits the caller. Calibrate an exact-input swap that barely crosses the boundary (adjust +/-1 wei), loop it under a flash loan, then withdraw the accumulated credit. Root causes: mulDiv floor vs ceil mismatch, unrounded vs tick-spaced ticks, Q64.96 precision loss not mirrored on the reverse mapping, per-caller withdrawable residue instead of a burn sink.

Virtual-balance cache poisoning (Yearn yETH, "16 wei -> 2.35e56 tokens"): weighted pools cache derived virtual balances for gas. A multi-bug chain: push the solver into a degenerate regime (`Pi` collapses to 0, LP over-minted), drain real liquidity while floor-division leaves cache dust, reach a live `prev_supply == 0` bootstrap state that trusts the stale cache, then a dust deposit hits unchecked subtraction and mints a near-infinite supply. Generalizes wherever cached balance-derivatives persist, partial updates truncate, iterative solvers reach degenerate states without reverting, internal accounting can diverge from real balances, and bootstrap/zero-supply paths reuse caches. Defenses: clear caches at `supply == 0`, recompute from ground truth on init, seal bootstrap as one-shot, assert solver domain, mint sanity bounds.

## Bypasses and variants
- Flash loans finance most economic attacks with zero long-lived capital; always model the exploit as a single-transaction, flash-funded sequence.
- Bitcoin-side, note the privacy-deanonymization angle (common-input-ownership, change-address detection, CoinJoin/PayJoin) as a distinct analysis track.

## Detection and defence

Audit methods worth their own note:
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
Mutation testing "tests the tests": surviving mutants (e.g. `[CR] '...=...' ==> '//...' --> UNCAUGHT`) reveal missing assertions that line/branch coverage hides, especially around auth, value-transfer invariants, revert paths, and boundaries (`==`, zero, max). Prefer AST/Tree-sitter engines (slither-mutate, mewt, MuTON) over regex. For scoping the engagement itself, the MITRE AADAPT matrix is a value-centric red-team backbone: map each value-bearing component to attacker techniques (flash-loan manipulation, oracle poisoning, signing abuse, cross-chain laundering) and rehearse each on a forked mainnet.

## Tools
Slither (static analysis + AST), Foundry/Hardhat (forked-mainnet simulation and PoC harnesses), Echidna/property fuzzing, slither-mutate/mewt/MuTON (mutation testing), forked mainnet to replay bytecode+storage+liquidity end-to-end without real funds. Threat modelling: MITRE AADAPT matrix.

## Sources

- HackTricks (blockchain), ingest slug `hacktricks-blockchain`.
