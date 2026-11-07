#![cfg(test)]

use crate::test_vector as tv;
use crate::types::{DataKey, Error, Proof, VerifyingKey};
use crate::{VeilproofRegistry, VeilproofRegistryClient};
use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
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

/// Ledgers until the contract instance's TTL runs out.
fn instance_ttl(s: &Setup) -> u32 {
    s.env
        .as_contract(&s.client.address, || s.env.storage().instance().get_ttl())
}

/// Moves the ledger forward without letting any entry expire.
fn advance_ledgers(s: &Setup, ledgers: u32) {
    let seq = s.env.ledger().sequence();
    s.env.ledger().set_sequence_number(seq + ledgers);
}

/// Ledgers per day at Soroban's 5 second close time, and the TTLs the contract
/// is expected to maintain.
const DAY: u32 = 17_280;

/// The instance holds the admin and the grace window, so it has to outlive its
/// default TTL for as long as the registry is in use.
#[test]
fn construction_extends_the_instance() {
    let s = setup();
    assert!(instance_ttl(&s) >= 89 * DAY);
}

/// Publishing a root renews the instance once it nears the threshold.
#[test]
fn publishing_extends_the_instance() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);

    advance_ledgers(&s, 65 * DAY);
    assert!(instance_ttl(&s) < 30 * DAY);

    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    assert!(instance_ttl(&s) >= 89 * DAY);
}

/// Verifying renews the instance and the entries verification reads, so a
/// credential in steady use cannot lose its issuer, circuit, or root.
#[test]
fn verifying_extends_what_it_reads() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));

    advance_ledgers(&s, 65 * DAY);
    s.client.verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    );

    let (issuer_ttl, circuit_ttl, roots_ttl) = s.env.as_contract(&s.client.address, || {
        let storage = s.env.storage();
        let persistent = storage.persistent();
        (
            persistent.get_ttl(&DataKey::Issuer(s.credential.clone())),
            persistent.get_ttl(&DataKey::Circuit(s.circuit.clone())),
            persistent.get_ttl(&DataKey::Roots(s.credential.clone())),
        )
    });
    assert!(issuer_ttl >= 89 * DAY);
    assert!(circuit_ttl >= 89 * DAY);
    assert!(roots_ttl >= 89 * DAY);
    assert!(instance_ttl(&s) >= 89 * DAY);
}

/// A handover completes only once the new address accepts it, and the old admin
/// loses privilege in that same step.
#[test]
fn admin_handover_moves_the_role() {
    let s = setup();
    let next = Address::generate(&s.env);

    s.client.propose_admin(&s.admin, &next);
    assert_eq!(s.client.pending_admin(), Some(next.clone()));
    // Nothing changes until it is accepted.
    assert_eq!(s.client.admin(), Some(s.admin.clone()));
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);

    s.client.accept_admin(&next);
    assert_eq!(s.client.admin(), Some(next.clone()));
    assert_eq!(s.client.pending_admin(), None);

    let aml = Symbol::new(&s.env, "aml");
    let res = s
        .client
        .try_register_issuer(&s.admin, &s.issuer, &aml, &s.circuit);
    assert_eq!(res, Err(Ok(Error::NotAdmin)));
    s.client.register_issuer(&next, &s.issuer, &aml, &s.circuit);
}

/// Only the admin can start a handover.
#[test]
fn non_admin_cannot_propose_admin() {
    let s = setup();
    let intruder = Address::generate(&s.env);
    let res = s.client.try_propose_admin(&intruder, &intruder);
    assert_eq!(res, Err(Ok(Error::NotAdmin)));
    assert_eq!(s.client.pending_admin(), None);
}

/// Only the proposed address can accept, and only while an offer stands.
#[test]
fn only_the_proposed_address_can_accept() {
    let s = setup();
    let next = Address::generate(&s.env);
    let intruder = Address::generate(&s.env);

    assert_eq!(
        s.client.try_accept_admin(&next),
        Err(Ok(Error::NotPendingAdmin))
    );

    s.client.propose_admin(&s.admin, &next);
    assert_eq!(
        s.client.try_accept_admin(&intruder),
        Err(Ok(Error::NotPendingAdmin))
    );
    assert_eq!(s.client.admin(), Some(s.admin.clone()));
}

/// The recovery path for a mistyped address: a second proposal replaces the
/// first, which can then no longer be accepted.
#[test]
fn a_new_proposal_replaces_the_old_one() {
    let s = setup();
    let mistyped = Address::generate(&s.env);
    let intended = Address::generate(&s.env);

    s.client.propose_admin(&s.admin, &mistyped);
    s.client.propose_admin(&s.admin, &intended);

    assert_eq!(
        s.client.try_accept_admin(&mistyped),
        Err(Ok(Error::NotPendingAdmin))
    );
    s.client.accept_admin(&intended);
    assert_eq!(s.client.admin(), Some(intended));
}

/// A completed handover cannot be accepted a second time.
#[test]
fn an_accepted_offer_cannot_be_reused() {
    let s = setup();
    let next = Address::generate(&s.env);
    s.client.propose_admin(&s.admin, &next);
    s.client.accept_admin(&next);
    assert_eq!(
        s.client.try_accept_admin(&next),
        Err(Ok(Error::NotPendingAdmin))
    );
}

/// Publishes `root` under the fixture credential, then supersedes it with an
/// unrelated root at `superseded_at`.
fn publish_then_supersede(s: &Setup, superseded_at: u64) {
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.env.ledger().set_timestamp(superseded_at);
    let other = BytesN::from_array(&s.env, &[9u8; 32]);
    s.client.publish_root(&s.issuer, &s.credential, &other);
}

fn try_real_verify(s: &Setup) -> Result<(), Error> {
    match s.client.try_verify_credential(
        &s.holder,
        &s.credential,
        &real_proof(&s.env),
        &nullifier(&s.env),
    ) {
        Ok(_) => Ok(()),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("unexpected invoke error: {e:?}"),
    }
}

/// The grace window exists for a proof generated just before a root update, so
/// it has to run from that update. A root that had been live for far longer
/// than the window still gets its full grace once superseded.
#[test]
fn grace_runs_from_the_update_not_the_original_publish() {
    let s = setup();
    let superseded_at = s.env.ledger().timestamp() + 10 * GRACE_SECONDS;
    publish_then_supersede(&s, superseded_at);

    s.env.ledger().set_timestamp(superseded_at + 1);
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// The window is inclusive: the last valid second is `superseded + grace`.
#[test]
fn grace_boundary_is_inclusive() {
    let s = setup();
    let superseded_at = s.env.ledger().timestamp() + 100;
    publish_then_supersede(&s, superseded_at);

    s.env.ledger().set_timestamp(superseded_at + GRACE_SECONDS);
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// One second past the boundary, the old root is no longer accepted.
#[test]
fn grace_ends_one_second_after_the_boundary() {
    let s = setup();
    let superseded_at = s.env.ledger().timestamp() + 100;
    publish_then_supersede(&s, superseded_at);

    s.env
        .ledger()
        .set_timestamp(superseded_at + GRACE_SECONDS + 1);
    assert_eq!(try_real_verify(&s), Err(Error::ProofInvalid));
}

/// A proof against the current root is unaffected by any amount of elapsed time.
#[test]
fn current_root_never_ages_out() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.env
        .ledger()
        .set_timestamp(s.env.ledger().timestamp() + 1000 * GRACE_SECONDS);
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// Only one previous root is retained. Two updates inside one window therefore
/// drop the older root at once, and this is deliberate: it bounds verification
/// to two pairing checks. An issuer updating in quick succession should expect
/// to invalidate proofs against the root before last.
#[test]
fn second_update_in_a_window_drops_the_older_root() {
    let s = setup();
    let superseded_at = s.env.ledger().timestamp() + 100;
    publish_then_supersede(&s, superseded_at);

    s.env.ledger().set_timestamp(superseded_at + 1);
    let third = BytesN::from_array(&s.env, &[10u8; 32]);
    s.client.publish_root(&s.issuer, &s.credential, &third);

    assert_eq!(try_real_verify(&s), Err(Error::ProofInvalid));
}

/// Republishing the root that is already current keeps it valid as the current
/// root, so no window applies to it.
#[test]
fn republishing_the_same_root_keeps_it_current() {
    let s = setup();
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
    s.env
        .ledger()
        .set_timestamp(s.env.ledger().timestamp() + 1000 * GRACE_SECONDS);
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// A window so large it would overflow saturates instead of trapping.
#[test]
fn enormous_grace_saturates_rather_than_overflows() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let holder = Address::from_string(&String::from_str(&env, FIXED_HOLDER));
    let credential = Symbol::new(&env, "kyc");
    let circuit = Symbol::new(&env, "membership");
    let contract_id = env.register(VeilproofRegistry, (admin.clone(), u64::MAX));
    let client = VeilproofRegistryClient::new(&env, &contract_id);
    client.register_circuit(&admin, &circuit, &verifying_key(&env));
    client.register_issuer(&admin, &issuer, &credential, &circuit);
    client.publish_root(&issuer, &credential, &root(&env));

    env.ledger().set_timestamp(env.ledger().timestamp() + 100);
    let other = BytesN::from_array(&env, &[9u8; 32]);
    client.publish_root(&issuer, &credential, &other);

    client.verify_credential(&holder, &credential, &real_proof(&env), &nullifier(&env));
    assert!(client.is_verified(&holder, &credential));
}

fn ready_to_verify(s: &Setup) {
    s.client
        .register_issuer(&s.admin, &s.issuer, &s.credential, &s.circuit);
    s.client
        .publish_root(&s.issuer, &s.credential, &root(&s.env));
}

/// A paused circuit refuses a valid proof, and the same proof verifies once it
/// is resumed: pausing consumes nothing.
#[test]
fn pause_blocks_verification_until_resumed() {
    let s = setup();
    ready_to_verify(&s);

    s.client.pause_circuit(&s.admin, &s.circuit);
    assert!(s.client.is_circuit_paused(&s.circuit));
    assert_eq!(try_real_verify(&s), Err(Error::CircuitPaused));
    assert!(!s
        .client
        .is_nullifier_used(&s.credential, &nullifier(&s.env)));

    s.client.unpause_circuit(&s.admin, &s.circuit);
    assert!(!s.client.is_circuit_paused(&s.circuit));
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// Consumers reading existing statuses must not break during a pause.
#[test]
fn reads_keep_working_while_paused() {
    let s = setup();
    ready_to_verify(&s);
    assert_eq!(try_real_verify(&s), Ok(()));

    s.client.pause_circuit(&s.admin, &s.circuit);

    assert!(s.client.is_verified(&s.holder, &s.credential));
    assert!(s.client.verified_at(&s.holder, &s.credential).is_some());
    let holders = vec![&s.env, s.holder.clone()];
    assert_eq!(
        s.client.are_verified(&holders, &s.credential).get(0),
        Some(true)
    );
    assert_eq!(s.client.current_root(&s.credential), Some(root(&s.env)));
}

/// A pause covers one circuit, leaving credentials on others untouched.
#[test]
fn pause_is_scoped_to_one_circuit() {
    let s = setup();
    let unaffected = Symbol::new(&s.env, "membership2");
    s.client
        .register_circuit(&s.admin, &unaffected, &verifying_key(&s.env));
    let aml = Symbol::new(&s.env, "aml");
    s.client
        .register_issuer(&s.admin, &s.issuer, &aml, &unaffected);
    s.client.publish_root(&s.issuer, &aml, &root(&s.env));
    ready_to_verify(&s);

    s.client.pause_circuit(&s.admin, &s.circuit);

    assert_eq!(try_real_verify(&s), Err(Error::CircuitPaused));
    s.client
        .verify_credential(&s.holder, &aml, &real_proof(&s.env), &nullifier(&s.env));
    assert!(s.client.is_verified(&s.holder, &aml));
}

/// Publishing stays open during a pause, since a root alone grants nothing.
#[test]
fn publishing_still_works_while_paused() {
    let s = setup();
    ready_to_verify(&s);
    s.client.pause_circuit(&s.admin, &s.circuit);

    let next = BytesN::from_array(&s.env, &[9u8; 32]);
    s.client.publish_root(&s.issuer, &s.credential, &next);
    assert_eq!(s.client.current_root(&s.credential), Some(next));
}

/// Pausing and resuming are admin-only, and a pause must name a real circuit.
#[test]
fn pause_is_admin_only_and_checks_the_circuit() {
    let s = setup();
    let intruder = Address::generate(&s.env);
    assert_eq!(
        s.client.try_pause_circuit(&intruder, &s.circuit),
        Err(Ok(Error::NotAdmin))
    );
    assert_eq!(
        s.client.try_unpause_circuit(&intruder, &s.circuit),
        Err(Ok(Error::NotAdmin))
    );
    let missing = Symbol::new(&s.env, "nope");
    assert_eq!(
        s.client.try_pause_circuit(&s.admin, &missing),
        Err(Ok(Error::CircuitNotFound))
    );
}

/// The behaviour rotation exists to fix: a revoked credential cannot simply be
/// registered again, and its roots survive the attempt.
#[test]
fn revoked_credential_cannot_be_reregistered() {
    let s = setup();
    ready_to_verify(&s);
    s.client.revoke_issuer(&s.admin, &s.credential);

    let replacement = Address::generate(&s.env);
    assert_eq!(
        s.client
            .try_register_issuer(&s.admin, &replacement, &s.credential, &s.circuit),
        Err(Ok(Error::IssuerExists))
    );
    assert_eq!(s.client.current_root(&s.credential), Some(root(&s.env)));
}

/// Revoking stops new roots, not proofs against the root already published.
#[test]
fn revoked_issuer_root_still_verifies() {
    let s = setup();
    ready_to_verify(&s);
    s.client.revoke_issuer(&s.admin, &s.credential);
    assert_eq!(try_real_verify(&s), Ok(()));
}

/// Rotation hands over publishing, and keeps roots and verified holders.
#[test]
fn rotation_preserves_roots_and_statuses() {
    let s = setup();
    ready_to_verify(&s);
    assert_eq!(try_real_verify(&s), Ok(()));

    let replacement = Address::generate(&s.env);
    s.client
        .rotate_issuer(&s.admin, &s.credential, &replacement);

    assert_eq!(s.client.issuer_of(&s.credential), Some(replacement.clone()));
    assert_eq!(s.client.current_root(&s.credential), Some(root(&s.env)));
    assert!(s.client.is_verified(&s.holder, &s.credential));

    let next = BytesN::from_array(&s.env, &[9u8; 32]);
    assert_eq!(
        s.client.try_publish_root(&s.issuer, &s.credential, &next),
        Err(Ok(Error::NotIssuer))
    );
    s.client.publish_root(&replacement, &s.credential, &next);
    assert_eq!(s.client.current_root(&s.credential), Some(next));
}

/// Rotation is how a revoked credential comes back.
#[test]
fn rotation_reactivates_a_revoked_credential() {
    let s = setup();
    ready_to_verify(&s);
    s.client.revoke_issuer(&s.admin, &s.credential);

    let replacement = Address::generate(&s.env);
    s.client
        .rotate_issuer(&s.admin, &s.credential, &replacement);
    let next = BytesN::from_array(&s.env, &[9u8; 32]);
    s.client.publish_root(&replacement, &s.credential, &next);
    assert_eq!(s.client.current_root(&s.credential), Some(next));
}

/// Neither an outsider nor the current issuer can rotate, and the credential
/// has to exist.
#[test]
fn rotation_is_admin_only() {
    let s = setup();
    ready_to_verify(&s);
    let replacement = Address::generate(&s.env);
    for caller in [Address::generate(&s.env), s.issuer.clone()] {
        assert_eq!(
            s.client
                .try_rotate_issuer(&caller, &s.credential, &replacement),
            Err(Ok(Error::NotAdmin))
        );
    }
    assert_eq!(s.client.issuer_of(&s.credential), Some(s.issuer.clone()));

    let missing = Symbol::new(&s.env, "nope");
    assert_eq!(
        s.client.try_rotate_issuer(&s.admin, &missing, &replacement),
        Err(Ok(Error::IssuerNotFound))
    );
}
