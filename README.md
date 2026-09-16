# veilproof-registry

An on-chain **zero-knowledge credential verifier and registry** for Soroban.

An issuer publishes a Merkle root over a set of credential holders — say,
"addresses that passed KYC". A holder proves they belong to that set with a
Groth16 zero-knowledge proof, **without revealing which member they are**, and
the contract verifies the proof on-chain using Soroban Protocol 25's native
BN254 pairing host function. A **nullifier**, derived deterministically from
the underlying credential, prevents the same credential being used to "verify"
twice under different addresses. Any other contract or party can then read
`is_verified(address, credential)` as a plain on-chain boolean.

## Why this matters

Compliance credentials — KYC status, accredited-investor status, jurisdiction
checks — today mean either trusting a centralized database or publishing
personal data on-chain. Protocol 25 added native BN254 pairing-check host
functions, making real on-chain zero-knowledge verification possible for the
first time on Stellar. veilproof-registry uses it so a holder can **prove**
compliance without disclosing the underlying data.

## Flow

```
   ┌──────────┐   register_issuer        ┌─────────────────────┐
   │  admin   │─────────────────────────▶│  veilproof-registry │
   └──────────┘                          │   (this contract)   │
                                         │                     │
   ┌──────────┐   publish_root(root)     │  issuer ─▶ root     │
   │  issuer  │─────────────────────────▶│           history   │
   └──────────┘                          │                     │
        │ (off-chain: builds the tree,   │                     │
        │  hands each holder a witness)  │                     │
        ▼                                │                     │
   ┌──────────┐                          │                     │
   │  holder  │  proves membership       │                     │
   │          │  off-chain (Groth16)     │                     │
   └────┬─────┘                          │                     │
        │  verify_credential(            │                     │
        │    proof, nullifier)           │  pairing_check ✔    │
        └─────────────────────────────▶  │  nullifier unused? ✔│
                                         │  ├─ burn nullifier   │
                                         │  └─ record verified  │
                                         └─────────┬───────────┘
                                                   │ is_verified(holder, cred) ─▶ bool
                                                   ▼
                                         ┌─────────────────────┐
                                         │ any other contract  │
                                         │ or party reads it   │
                                         └─────────────────────┘
```

The root is **never** taken from the caller at verification time — it is the
issuer's current root (or the immediately previous one, within a grace
window). A proof therefore cannot claim membership in a root the issuer never
published.

## BN254 Encoding Notes

**This is the single most important section in the repository.** Soroban's
native BN254 host functions expect a specific byte encoding, and it is the
*opposite* of the arkworks/snarkjs defaults in three ways. Getting any of them
wrong makes `pairing_check` silently return `false` (or trap) rather than
verify. Everything here is taken from the authoritative spec,
[CAP-0074][cap74], cross-checked against the `soroban-sdk` 25.3.2 source.

| Element  | Encoding                                                      | Length     |
| -------- | ------------------------------------------------------------ | ---------- |
| `Fp`     | **big-endian** unsigned integer                              | 32 bytes   |
| `Fp2`    | `be(c1) ‖ be(c0)` — **c1 first, then c0**                    | 64 bytes   |
| `Fr`     | scalar as `U256` (big-endian 32 bytes)                       | 32 bytes   |
| G1 point | `be(X) ‖ be(Y)` — **uncompressed**                           | 64 bytes   |
| G2 point | `be(X.c1) ‖ be(X.c0) ‖ be(Y.c1) ‖ be(Y.c0)` — **uncompressed** | 128 bytes |
| ∞ (zero) | all-zero bytes                                               | —          |

The three traps, each the reverse of a common library default:

1. **Big-endian.** arkworks serializes field elements little-endian. Every
   coordinate must be byte-reversed on the way out.
2. **Uncompressed.** No compression flag bits — the top two bits of the first
   byte must be unset. Many libraries emit compressed points by default.
3. **Fp2 ordered `c1 ‖ c0`** (imaginary part first). arkworks stores `(c0, c1)`
   internally, so G2 limbs must be swapped. This matches Ethereum's alt_bn128
   precompile convention, which is the same curve.

The BN254 base-field modulus is
`0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`, and the
scalar-field order is
`0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.

This encoding is produced by [`tools/testvector`](tools/testvector) (see
`g1_bytes` / `g2_bytes`) and consumed by the contract in `src/lib.rs`
(`groth16_verify`, `scalar_be`). The
[`real_proof_verifies_once`](src/test.rs) test proves the round trip: a genuine
Groth16 proof, serialized this way, verifies through the real native
`pairing_check`. If any encoding rule above were wrong, that test would fail.

### Groth16 verification equation

With `vk_x = IC[0] + root·IC[1] + nullifier·IC[2]`, the contract checks

```
e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
```

which is arkworks' `e(A,B) = e(alpha,beta)·e(vk_x,gamma)·e(C,delta)` moved to
one side, negating `A` only (via the SDK's native G1 negation). This is passed
to `bn254.pairing_check(vp1, vp2)` as the two vectors
`[−A, alpha, vk_x, C]` and `[B, beta, gamma, delta]`.

## Contract API

| Function                                                       | Auth   | Purpose                                              |
| -------------------------------------------------------------- | ------ | ---------------------------------------------------- |
| `__constructor(admin, vk, grace_seconds)`                      | —      | Set admin, fix the verifying key, set the grace window |
| `register_issuer(admin, issuer, credential)`                   | admin  | Authorize an issuer for a named credential           |
| `revoke_issuer(admin, credential)`                             | admin  | Deactivate that issuer                               |
| `publish_root(issuer, credential, merkle_root)`                | issuer | Publish/update the Merkle root (prior root kept)     |
| `verify_credential(holder, credential, proof, nullifier)`      | holder | Verify a proof, burn the nullifier, record the holder |
| `is_verified(holder, credential) -> bool`                      | view   | The on-chain compliance boolean                      |
| `verified_at`, `is_nullifier_used`, `current_root`, `issuer_of`, `admin` | view | Registry reads                             |

## Trust model

- **The circuit is the root of trust.** The contract verifies that a proof is
  correctly formed against the fixed verifying key. It **cannot** tell whether
  the circuit that produced that key is sound. A flawed circuit (e.g. one that
  doesn't actually bind the Merkle root, or computes a guessable nullifier)
  produces proofs this contract will happily accept. The circuit lives in the
  sibling `veilproof-server`; the minimal MiMC circuit in `tools/testvector`
  exists only to generate a real test vector.
- **The verifying key is fixed at construction and never updatable.** A
  different circuit is a different key and a *new deployment*. This is the
  simplest, safest MVP choice — there is no admin function to swap the circuit
  in place, so no one can silently repoint verification at a different
  statement.
- **The issuer is trusted for set membership.** Whoever the admin authorizes as
  issuer defines "who is in the set" by publishing roots. The ZK property is
  that holders prove membership *without revealing which member*; it is not a
  claim that the issuer's set is itself correct.
- **Known limitation — the MVP proof does not bind the holder address.** The
  public inputs are `(root, nullifier)` only. A proof observed in the mempool
  could be submitted by another party under *their* address, consuming the
  nullifier and recording themselves (not the original holder) as verified.
  The nullifier still guarantees the credential can be spent only *once* — this
  only changes *who* gets that one verification. Binding an address-derived
  public input into the circuit is the fix, tracked as a
  [future issue](#scope-and-future-work).

## Storage & TTL

Roots, nullifiers, and verification records live in **persistent** storage and
their TTL is extended on every write (`bump`). This matters most for
nullifiers: a used-nullifier entry that silently expired and was pruned would
reopen the replay hole.

Soroban's state model backs this up. Persistent entries are **archived, not
deleted**, when their TTL lapses, and are restored *with their original value*.
A used nullifier can therefore be temporarily archived but never reset to
"unused" — a re-submission touching an archived entry must restore it first,
and restoration brings back `used = true`. The TTL bump reduces the need for
restoration in practice; the archival guarantee is the backstop.

## Toolchain

Verified versions used to build and test this contract:

| Component            | Version                                 |
| -------------------- | --------------------------------------- |
| `soroban-sdk`        | **`=25.3.2`** (pinned; first BN254 support is 25.x) |
| Rust wasm target     | **`wasm32v1-none`**                     |
| Stellar CLI          | `27.1.0` (any `>= 25` supports Protocol 25) |
| Protocol             | 25 "X-Ray" — testnet 2026-01-07, mainnet 2026-01-22 |
| arkworks (test tool) | `ark-bn254` / `ark-groth16` / `ark-r1cs-std` `0.5` |

> **Dependency note:** the lockfile pins `ed25519-dalek` to `2.2.0`. Its 3.0.0
> release changed a `rand_core` trait bound that `soroban-env-host` 25.0.1's
> test PRNG does not satisfy, breaking `cargo test`. Keep the pin until the SDK
> moves up.

## Build, test, deploy

```sh
# Build the wasm contract
stellar contract build
# → target/wasm32v1-none/release/veilproof_registry.wasm

# Run the full test suite (native; runs the real BN254 host)
cargo test

# Regenerate the real Groth16 test vector (deterministic)
cargo run --manifest-path tools/testvector/Cargo.toml --release
```

Deploying to testnet (the verifying key and grace window are constructor
arguments — see `src/test.rs` for how the key bytes are assembled from the
generated vector):

```sh
stellar contract deploy \
  --wasm target/wasm32v1-none/release/veilproof_registry.wasm \
  --source <your-key> --network testnet \
  -- --admin <admin-address> --vk <vk> --grace_seconds 3600
```

## Scope and future work

The MVP supports **one fixed circuit** — Merkle-membership + nullifier. This is
intentional. Deliberately out of scope, each a flagged contributor issue:

- **Multiple circuit types / arbitrary schemas.** The verifying key is fixed at
  construction; supporting several circuits means a registry of keys and a
  circuit selector.
- **Binding the holder address into the proof**, closing the front-running gap
  described in the trust model.
- **A batch or paged view** for reading many verification statuses at once.

## Repository layout

```
src/lib.rs          the contract
src/types.rs        storage types, errors, events
src/test.rs         full test suite, incl. the real-proof verification
src/test_vector.rs  GENERATED — a real proof in Soroban's BN254 encoding
tools/testvector/   native tool that generates src/test_vector.rs
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

[cap74]: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0074.md
