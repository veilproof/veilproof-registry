#![cfg(test)]

use crate::test_vector as tv;
use crate::types::{Error, Proof, VerifyingKey};
use crate::{VeilproofRegistry, VeilproofRegistryClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, BytesN, Env, String, Symbol};

const GRACE_SECONDS: u64 = 3600;

/// The holder address the committed test vector binds its proof to. Proofs are
/// address-bound, so the verifying holder must be this exact address.
const FIXED_HOLDER: &str = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";

fn verifying_key(env: &Env) -> VerifyingKey {
    VerifyingKey {
        alpha_g1: BytesN::from_array(env, &tv::ALPHA_G1),
        beta_g2: BytesN::from_array(env, &tv::BETA_G2),
        gamma_g2: BytesN::from_array(env, &tv::GAMMA_G2),
        delta_g2: BytesN::from_array(env, &tv::DELTA_G2),
        ic: vec![
            env,
            BytesN::from_array(env, &tv::IC[0]),
            BytesN::from_array(env, &tv::IC[1]),
            BytesN::from_array(env, &tv::IC[2]),
            BytesN::from_array(env, &tv::IC[3]),
        ],
    }
}

fn real_proof(env: &Env) -> Proof {
    Proof {
        a: BytesN::from_array(env, &tv::PROOF_A),
        b: BytesN::from_array(env, &tv::PROOF_B),
        c: BytesN::from_array(env, &tv::PROOF_C),
    }
}

fn root(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &tv::PUB_ROOT)
}

fn nullifier(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &tv::PUB_NULLIFIER)
}

struct Setup {
    env: Env,
    client: VeilproofRegistryClient<'static>,
    admin: Address,
    issuer: Address,
    holder: Address,
    credential: Symbol,
    circuit: Symbol,
}

fn setup() -> Setup {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let holder = Address::from_string(&String::from_str(&env, FIXED_HOLDER));
    let credential = Symbol::new(&env, "kyc");

    let contract_id = env.register(VeilproofRegistry, (admin.clone(), GRACE_SECONDS));
    let client = VeilproofRegistryClient::new(&env, &contract_id);

    let circuit = Symbol::new(&env, "membership");
    client.register_circuit(&admin, &circuit, &verifying_key(&env));

    Setup {
        env,
        client,
        admin,
        issuer,
        holder,
        credential,
        circuit,
    }
}

/// The keystone test: a real Groth16 proof, produced by tools/testvector
/// against a real Merkle tree, verifies through the native BN254 pairing
/// check. If the CAP-0074 encoding were wrong, this would fail.
#[test]
fn real_proof_verifies_once() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    assert!(!s.client.is_verified(&s.holder, &s.credential));
    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );

    assert!(s.client.is_verified(&s.holder, &s.credential));
    assert!(s
        .client
        .is_nullifier_used(&s.credential, &nullifier(&s.env)));
    assert!(s.client.verified_at(&s.holder, &s.credential).is_some());
}

/// Replay with the same nullifier is rejected, even under a different holder
/// address — the core double-use guarantee.
#[test]
fn replay_with_same_nullifier_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );

    // A different address, the same nullifier: still rejected.
    let attacker = Address::generate(&s.env);
    let res = s.client.try_verify_credential(
        &attacker,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert_eq!(res, Err(Ok(Error::NullifierUsed)));
    // The attacker was not recorded as verified.
    assert!(!s.client.is_verified(&attacker, &s.credential));
}

/// A proof made against one root does not verify against a different current
/// root once the grace window has passed.
#[test]
fn proof_against_stale_root_rejected_after_grace() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    // Supersede with a different root, then move past the grace window.
    let other = BytesN::from_array(&s.env, &[9u8; 32]);
    s.client.publish_root(&s.issuer, &s.credential, &other);
    s.env
        .ledger()
        .set_timestamp(s.env.ledger().timestamp() + GRACE_SECONDS + 1);

    let res = s.client.try_verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));
}

/// Within the grace window a proof against the just-superseded root still
/// verifies.
#[test]
fn proof_against_previous_root_verifies_within_grace() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    let other = BytesN::from_array(&s.env, &[9u8; 32]);
    s.client.publish_root(&s.issuer, &s.credential, &other);
    // Still inside the window.
    s.env
        .ledger()
        .set_timestamp(s.env.ledger().timestamp() + GRACE_SECONDS - 1);

    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert!(s.client.is_verified(&s.holder, &s.credential));
}

/// An address that is not the registered issuer cannot publish a root.
#[test]
fn unauthorized_issuer_publish_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);

    let impostor = Address::generate(&s.env);
    let res = s
        .client
        .try_publish_root(&impostor, &s.credential, &root(&s.env));
    assert_eq!(res, Err(Ok(Error::NotIssuer)));
}

/// A revoked issuer cannot publish, but previously published roots remain.
#[test]
fn revoked_issuer_cannot_publish() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.client.revoke_issuer(&s.admin, &s.credential);

    let res = s
        .client
        .try_publish_root(&s.issuer, &s.credential, &root(&s.env));
    assert_eq!(res, Err(Ok(Error::NotIssuer)));
    // The last good root is still readable.
    assert_eq!(s.client.current_root(&s.credential), Some(root(&s.env)));
}

/// Registering two issuers for the same credential name is rejected.
#[test]
fn duplicate_issuer_registration_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    let other = Address::generate(&s.env);
    let res = s
        .client
        .try_register_issuer(&s.admin, &other, &s.credential, &s.circuit);
    assert_eq!(res, Err(Ok(Error::IssuerExists)));
}

/// A non-admin cannot register issuers.
#[test]
fn non_admin_cannot_register_issuer() {
    let s = setup();
    let not_admin = Address::generate(&s.env);
    let res = s
        .client
        .try_register_issuer(&not_admin, &s.issuer, &s.credential, &s.circuit);
    assert_eq!(res, Err(Ok(Error::NotAdmin)));
}

/// Verifying before any root is published is rejected with NoRoot.
#[test]
fn verify_without_root_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    let res = s.client.try_verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert_eq!(res, Err(Ok(Error::NoRoot)));
}

/// A tampered proof (valid structure, wrong point) does not verify.
#[test]
fn tampered_proof_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    // Swap A and C — both are valid on-curve G1 points, so this exercises the
    // pairing check itself returning false rather than an on-curve rejection.
    let good = real_proof(&s.env);
    let tampered = Proof {
        a: good.c.clone(),
        b: good.b.clone(),
        c: good.a.clone(),
    };
    let res =
        s.client
            .try_verify_credential(&s.holder, &s.credential, &tampered, &nullifier(&s.env));
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));
    assert!(!s.client.is_verified(&s.holder, &s.credential));
}

/// Full lifecycle across two credentials sharing a contract.
#[test]
fn full_lifecycle() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    assert_eq!(s.client.issuer_of(&s.credential), Some(s.issuer.clone()));
    assert_eq!(s.client.admin(), Some(s.admin.clone()));
    assert_eq!(s.client.current_root(&s.credential), Some(root(&s.env)));

    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert!(s.client.is_verified(&s.holder, &s.credential));
}

/// The batch view returns one result per holder, in order, and rejects an
/// oversized query.
#[test]
fn are_verified_batch() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );

    let other = Address::generate(&s.env);
    let holders = soroban_sdk::vec![&s.env, s.holder.clone(), other.clone()];
    let results = s.client.are_verified(&holders, &s.credential);
    assert_eq!(results.get(0), Some(true)); // the verified holder
    assert_eq!(results.get(1), Some(false)); // never verified

    // An oversized batch is rejected.
    let mut big = soroban_sdk::Vec::new(&s.env);
    for _ in 0..(crate::MAX_BATCH + 1) {
        big.push_back(Address::generate(&s.env));
    }
    let res = s.client.try_are_verified(&big, &s.credential);
    assert_eq!(res, Err(Ok(Error::BatchTooLarge)));
}

/// The address-binding guarantee: a proof made for one holder cannot be
/// submitted by another, even before the nullifier is spent. This is the
/// front-running fix — the stolen proof carries the original holder's addr as a
/// public input, so a different caller fails the pairing check.
#[test]
fn stolen_proof_under_other_address_rejected() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    // A different holder submits the (valid, unused) proof first.
    let attacker = Address::generate(&s.env);
    let res = s.client.try_verify_credential(
        &attacker,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert_eq!(res, Err(Ok(Error::ProofInvalid)));
    // The attacker is not verified, and the nullifier is not consumed, so the
    // real holder can still use it.
    assert!(!s.client.is_verified(&attacker, &s.credential));
    assert!(!s
        .client
        .is_nullifier_used(&s.credential, &nullifier(&s.env)));
    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert!(s.client.is_verified(&s.holder, &s.credential));
}

/// A circuit name is register-once; re-registering is rejected so a key can't
/// be silently repointed.
#[test]
fn duplicate_circuit_rejected() {
    let s = setup();
    let res = s
        .client
        .try_register_circuit(&s.admin, &s.circuit, &verifying_key(&s.env));
    assert_eq!(res, Err(Ok(Error::CircuitExists)));
}

/// Registering an issuer against an unknown circuit is rejected.
#[test]
fn unknown_circuit_for_issuer_rejected() {
    let s = setup();
    let missing = Symbol::new(&s.env, "nope");
    let res = s
        .client
        .try_register_issuer(&s.admin, &s.issuer, &s.credential, &missing);
    assert_eq!(res, Err(Ok(Error::CircuitNotFound)));
}

/// Two circuits coexist: a credential on a second registered circuit verifies
/// independently. (Here the two share a verifying key; in practice they would
/// differ in depth, hash, or setup while keeping the same public-input schema.)
#[test]
fn second_circuit_verifies() {
    let s = setup();
    let circuit2 = Symbol::new(&s.env, "membership2");
    s.client
        .register_circuit(&s.admin, &circuit2, &verifying_key(&s.env));

    let credential2 = Symbol::new(&s.env, "aml");
    s.client
        .register_issuer(&s.admin, &s.issuer, &credential2, &circuit2);
    s.client
        .publish_root(&s.issuer, &credential2, &root(&s.env));

    assert_eq!(s.client.circuit_of(&credential2), Some(circuit2));
    s.client.verify_credential(
        &s.holder,
        &credential2,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );
    assert!(s.client.is_verified(&s.holder, &credential2));
}
