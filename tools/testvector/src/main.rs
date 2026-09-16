//! Generates one real Groth16 test vector for veilproof-registry.
//!
//! This is a development tool, not part of the contract. It builds a small
//! real Merkle tree, proves membership of one leaf with a Groth16 proof over
//! BN254, self-verifies with arkworks, then serializes the verifying key,
//! the proof and the public inputs into the EXACT byte encoding Soroban's
//! native BN254 host functions expect (CAP-0074): big-endian field elements,
//! uncompressed points, and Fp2 ordered c1 then c0. The result is written to
//! ../../src/test_vector.rs as byte-array constants the contract test uses.
//!
//! The circuit hash here is a minimal MiMC — deliberately a throwaway proving
//! side whose only job is to produce a genuine proof, exactly as the project
//! brief anticipated. The production circuit lives in veilproof-server.

use std::fmt::Write as _;
use std::fs;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::{Boolean, CondSelectGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// MiMC rounds. Enough to be a genuine permutation; the proof's soundness
/// comes from Groth16, not from this count.
const ROUNDS: usize = 91;
/// Merkle tree depth for the test vector.
const DEPTH: usize = 4;
/// Domain separators so a leaf commitment and a nullifier derived from the
/// same secret are different hashes.
const LEAF_DOMAIN: u64 = 1;
const NULLIFIER_DOMAIN: u64 = 2;

/// The holder address the test vector binds to. The contract derives the same
/// field element from `holder.to_string()`, so the registry test uses this
/// exact address. Any valid Stellar strkey works; this is a throwaway one.
const FIXED_HOLDER: &str = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";

/// Bind a Stellar address to a field element: `Fr(sha256(strkey) mod r)`. The
/// contract computes the identical value via `env.crypto().sha256` over the
/// same strkey bytes, reduced mod r — so a proof only verifies for the address
/// it was generated for.
fn address_field(strkey: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&Sha256::digest(strkey.as_bytes()))
}

/// Deterministic round constants, so the emitted vector is reproducible.
fn round_constants() -> Vec<Fr> {
    let mut cs = Vec::with_capacity(ROUNDS);
    let mut state: u128 = 0xDEAD_BEEF_CAFE_BABE_0123_4567_89AB_CDEF;
    for _ in 0..ROUNDS {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        cs.push(Fr::from(state));
    }
    cs
}

// --- native MiMC (must match the gadget exactly) ---------------------------

fn mimc_native(mut x: Fr, k: Fr, constants: &[Fr]) -> Fr {
    for c in constants {
        let t = x + k + c;
        let t2 = t * t;
        let t4 = t2 * t2;
        x = t4 * t; // t^5
    }
    x + k
}

fn hash2_native(l: Fr, r: Fr, constants: &[Fr]) -> Fr {
    mimc_native(l, r, constants) + l + r
}

// --- gadget MiMC -----------------------------------------------------------

fn mimc_gadget(
    x: &FpVar<Fr>,
    k: &FpVar<Fr>,
    constants: &[Fr],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut x = x.clone();
    for c in constants {
        let t = &x + k + FpVar::constant(*c);
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        x = &t4 * &t;
    }
    Ok(&x + k)
}

fn hash2_gadget(
    l: &FpVar<Fr>,
    r: &FpVar<Fr>,
    constants: &[Fr],
) -> Result<FpVar<Fr>, SynthesisError> {
    let h = mimc_gadget(l, r, constants)?;
    Ok(&h + l + r)
}

// --- circuit ---------------------------------------------------------------

#[derive(Clone)]
struct MerkleCircuit {
    constants: Vec<Fr>,
    // public inputs
    root: Option<Fr>,
    nullifier: Option<Fr>,
    addr: Option<Fr>,
    // private witnesses
    secret: Option<Fr>,
    path_elements: Option<Vec<Fr>>,
    path_indices: Option<Vec<bool>>,
}

impl ConstraintSynthesizer<Fr> for MerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // The holder address, bound as a public input. It is not tied to the
        // witness — the verifier supplies it (derived from the caller) and the
        // proof only checks out for that value, which is what prevents a proof
        // being replayed under a different address. One multiplication gate
        // keeps it a real part of the constraint system.
        let addr = FpVar::new_input(cs.clone(), || {
            self.addr.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _addr_bound = &addr * &addr;
        let secret = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // leaf = H(secret, LEAF_DOMAIN)
        let leaf_domain = FpVar::constant(Fr::from(LEAF_DOMAIN));
        let mut cur = hash2_gadget(&secret, &leaf_domain, &self.constants)?;

        for i in 0..DEPTH {
            let sib = FpVar::new_witness(cs.clone(), || {
                self.path_elements
                    .as_ref()
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let bit = Boolean::new_witness(cs.clone(), || {
                self.path_indices
                    .as_ref()
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            // bit = true means `cur` is the right child, so hash(sibling, cur).
            let left = FpVar::conditionally_select(&bit, &sib, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sib)?;
            cur = hash2_gadget(&left, &right, &self.constants)?;
        }
        cur.enforce_equal(&root)?;

        // nullifier = H(secret, NULLIFIER_DOMAIN), address-independent so the
        // same secret always yields the same nullifier.
        let null_domain = FpVar::constant(Fr::from(NULLIFIER_DOMAIN));
        let null_calc = hash2_gadget(&secret, &null_domain, &self.constants)?;
        null_calc.enforce_equal(&nullifier)?;

        Ok(())
    }
}

// --- native tree ----------------------------------------------------------

struct Witness {
    root: Fr,
    nullifier: Fr,
    secret: Fr,
    path_elements: Vec<Fr>,
    path_indices: Vec<bool>,
}

fn build_witness(constants: &[Fr]) -> Witness {
    let secret = Fr::from(1234567890u64);
    let leaf = hash2_native(secret, Fr::from(LEAF_DOMAIN), constants);

    // A full tree of 2^DEPTH leaves; our leaf sits at index 0, the rest are
    // arbitrary distinct values standing in for other credential holders.
    let mut level: Vec<Fr> = (0..(1usize << DEPTH))
        .map(|j| if j == 0 { leaf } else { Fr::from(1000u64 + j as u64) })
        .collect();

    let mut siblings = Vec::new();
    let mut indices = Vec::new();
    let mut idx = 0usize;
    for _ in 0..DEPTH {
        let sib = level[idx ^ 1];
        siblings.push(sib);
        indices.push(idx & 1 == 1);
        let mut next = Vec::with_capacity(level.len() / 2);
        for j in (0..level.len()).step_by(2) {
            next.push(hash2_native(level[j], level[j + 1], constants));
        }
        level = next;
        idx >>= 1;
    }
    let root = level[0];
    let nullifier = hash2_native(secret, Fr::from(NULLIFIER_DOMAIN), constants);

    Witness {
        root,
        nullifier,
        secret,
        path_elements: siblings,
        path_indices: indices,
    }
}

// --- Soroban BN254 serialization (CAP-0074) -------------------------------

/// A base-field element as 32 big-endian bytes.
fn fq_be(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_be(); // 32 bytes for BN254 Fq
    out.copy_from_slice(&bytes);
    out
}

/// A scalar as 32 big-endian bytes.
fn fr_be(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_be();
    out.copy_from_slice(&bytes);
    out
}

/// G1 point: be(X) || be(Y), uncompressed, 64 bytes. Infinity = all zeros.
fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.infinity {
        return out;
    }
    out[..32].copy_from_slice(&fq_be(&p.x));
    out[32..].copy_from_slice(&fq_be(&p.y));
    out
}

/// G2 point: be(X.c1) || be(X.c0) || be(Y.c1) || be(Y.c0), uncompressed, 128
/// bytes. Note the c1-before-c0 order — this is the opposite of arkworks'
/// internal (c0, c1) storage, and getting it wrong makes pairing_check fail.
fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.infinity {
        return out;
    }
    let x: &Fq2 = &p.x;
    let y: &Fq2 = &p.y;
    out[0..32].copy_from_slice(&fq_be(&x.c1));
    out[32..64].copy_from_slice(&fq_be(&x.c0));
    out[64..96].copy_from_slice(&fq_be(&y.c1));
    out[96..128].copy_from_slice(&fq_be(&y.c0));
    out
}

// --- emit -----------------------------------------------------------------

fn hex_array(bytes: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "0x{:02x}", b).unwrap();
    }
    s.push(']');
    s
}

fn emit(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, w: &Witness, addr: Fr) -> String {
    let mut out = String::new();
    let p = &mut out;

    writeln!(p, "// GENERATED by tools/testvector — do not edit by hand.").unwrap();
    writeln!(
        p,
        "// A real Groth16 proof (BN254) for the MiMC Merkle-membership circuit,"
    )
    .unwrap();
    writeln!(
        p,
        "// serialized in Soroban's native encoding (CAP-0074). Regenerate with:"
    )
    .unwrap();
    writeln!(p, "//   cargo run -p veilproof-testvector --bin gen-test-vector").unwrap();
    writeln!(p, "#![allow(clippy::all, dead_code)]").unwrap();
    writeln!(p).unwrap();

    writeln!(
        p,
        "pub const ALPHA_G1: [u8; 64] = {};",
        hex_array(&g1_bytes(&vk.alpha_g1))
    )
    .unwrap();
    writeln!(
        p,
        "pub const BETA_G2: [u8; 128] = {};",
        hex_array(&g2_bytes(&vk.beta_g2))
    )
    .unwrap();
    writeln!(
        p,
        "pub const GAMMA_G2: [u8; 128] = {};",
        hex_array(&g2_bytes(&vk.gamma_g2))
    )
    .unwrap();
    writeln!(
        p,
        "pub const DELTA_G2: [u8; 128] = {};",
        hex_array(&g2_bytes(&vk.delta_g2))
    )
    .unwrap();

    writeln!(p, "pub const IC_LEN: usize = {};", vk.gamma_abc_g1.len()).unwrap();
    writeln!(p, "pub const IC: [[u8; 64]; {}] = [", vk.gamma_abc_g1.len()).unwrap();
    for ic in &vk.gamma_abc_g1 {
        writeln!(p, "    {},", hex_array(&g1_bytes(ic))).unwrap();
    }
    writeln!(p, "];").unwrap();

    writeln!(
        p,
        "pub const PROOF_A: [u8; 64] = {};",
        hex_array(&g1_bytes(&proof.a))
    )
    .unwrap();
    writeln!(
        p,
        "pub const PROOF_B: [u8; 128] = {};",
        hex_array(&g2_bytes(&proof.b))
    )
    .unwrap();
    writeln!(
        p,
        "pub const PROOF_C: [u8; 64] = {};",
        hex_array(&g1_bytes(&proof.c))
    )
    .unwrap();

    writeln!(
        p,
        "pub const PUB_ROOT: [u8; 32] = {};",
        hex_array(&fr_be(&w.root))
    )
    .unwrap();
    writeln!(
        p,
        "pub const PUB_NULLIFIER: [u8; 32] = {};",
        hex_array(&fr_be(&w.nullifier))
    )
    .unwrap();
    writeln!(
        p,
        "pub const PUB_ADDR: [u8; 32] = {};",
        hex_array(&fr_be(&addr))
    )
    .unwrap();

    out
}

fn main() {
    let constants = round_constants();
    let w = build_witness(&constants);

    // Reproducible setup + proof.
    let mut rng = ChaCha20Rng::seed_from_u64(0xF00D_BEEF);

    let addr = address_field(FIXED_HOLDER);
    let setup_circuit = MerkleCircuit {
        constants: constants.clone(),
        root: None,
        nullifier: None,
        addr: None,
        secret: None,
        path_elements: None,
        path_indices: None,
    };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).expect("setup");

    let prove_circuit = MerkleCircuit {
        constants: constants.clone(),
        root: Some(w.root),
        nullifier: Some(w.nullifier),
        addr: Some(addr),
        secret: Some(w.secret),
        path_elements: Some(w.path_elements.clone()),
        path_indices: Some(w.path_indices.clone()),
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).expect("prove");

    // Self-check with arkworks before trusting the bytes.
    let public_inputs = vec![w.root, w.nullifier, addr];
    let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).expect("verify");
    assert!(ok, "arkworks self-verification failed — aborting");

    // Sanity: infinity handling and non-zero coordinates.
    assert!(!proof.a.infinity && !proof.c.infinity);
    assert!(!vk.alpha_g1.is_zero());

    let src = emit(&vk, &proof, &w, addr);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/test_vector.rs");
    fs::write(path, src).expect("write test_vector.rs");
    println!("arkworks self-verify: OK");
    println!("public inputs: root={}, nullifier={}", w.root, w.nullifier);
    println!("wrote {}", path);
}
