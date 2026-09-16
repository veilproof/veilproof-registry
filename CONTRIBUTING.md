# Contributing to veilproof-registry

Thanks for your interest. This is an experimental, unaudited contract doing
on-chain zero-knowledge verification, so contributions that improve
correctness, testing, and the honesty of the documentation are especially
welcome.

## Ground rules

- **Never weaken the replay guarantee.** The nullifier set is the whole point.
  A change that lets the same nullifier verify twice — including through
  storage expiry — is a bug, not a feature.
- **Do not guess at BN254 encoding.** The byte layout is documented in the
  README's "BN254 Encoding Notes" with a CAP-0074 citation. If you change
  anything touching serialization, cite the authoritative source and prove it
  with a real proof through `pairing_check`, not a synthetic byte string.
- **Keep the verifying key fixed at construction** unless you are deliberately
  implementing circuit updatability — and if you do, treat it as the breaking,
  admin-gated, security-critical change it is, with tests.

## Development

```sh
cargo test                # full suite, runs the real BN254 host
cargo fmt --all           # formatting (CI checks this)
cargo clippy --all-targets -- -D warnings
stellar contract build    # wasm build (CI checks this)
```

Toolchain versions are pinned and documented in the README. The lockfile pins
`ed25519-dalek` to `2.2.0` for a reason noted there — do not bump it casually.

## The test vector

`src/test_vector.rs` is **generated** by `tools/testvector` and committed. It
is a genuine Groth16 proof for a real Merkle tree, serialized in Soroban's
encoding. Regenerate it deterministically with:

```sh
cargo run --manifest-path tools/testvector/Cargo.toml --release
```

If you change the circuit or the encoding, regenerate the vector and make sure
`real_proof_verifies_once` still passes — that test is the guarantee the whole
pipeline is byte-correct end to end.

## Pull requests

- One focused change per PR, with a clear description of *why*.
- Add or update tests. A change to verification logic without a test that would
  have caught the bug is not ready.
- `cargo fmt`, `clippy -D warnings`, `cargo test`, and `stellar contract build`
  must all pass.
- Be honest in docs about what is and isn't guaranteed. This project's value is
  partly that it states its limitations plainly (see the trust model).

## Reporting security issues

This contract is unaudited and experimental. If you find a soundness or
replay-protection issue, please open an issue describing the exact conditions —
the precise inputs and state that trigger it — so it can be reproduced.
