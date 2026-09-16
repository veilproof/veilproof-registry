#![no_std]
//! veilproof-registry: an on-chain ZK credential verifier and registry.
//!
//! An issuer publishes a Merkle root over a set of credential holders. A
//! holder proves membership in that set with a Groth16 zero-knowledge proof
//! — without revealing which member they are — and the contract verifies the
//! proof on-chain using Soroban Protocol 25's native BN254 pairing host
//! function. A nullifier, deterministic from the underlying credential,
//! prevents the same credential being "spent" twice under different
//! addresses.
//!
//! UNAUDITED. This is new territory (native Soroban ZK verification). The
//! security of the whole system also depends on the soundness of the circuit
//! that produced the verifying key — the contract verifies proofs correctly
//! formed against a given key; it cannot detect a flawed circuit. See README.

mod types;

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_vector;

use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr};
use soroban_sdk::{
    contract, contractimpl, panic_with_error, vec, Address, Bytes, BytesN, Env, Symbol, Vec, U256,
};

use types::{
    CredentialVerified, DataKey, Error, IssuerConfig, IssuerRegistered, IssuerRevoked,
    NullifierKey, Proof, RootHistory, RootPublished, VerifiedKey, VerifyingKey,
};

/// Public inputs for the fixed circuit are (root, nullifier), so the IC
/// vector has one constant term plus two, i.e. length 3.
const EXPECTED_IC_LEN: u32 = 3;

/// Upper bound on a batch verification query, to keep the read budget bounded.
pub const MAX_BATCH: u32 = 100;

// Persistent-storage TTL management. A used-nullifier entry that silently
// expired and was pruned would reopen the replay hole, so persistent entries
// are extended on every write. See the README's storage-TTL notes for the
// archival-restore guarantee that backs this up.
const DAY_LEDGERS: u32 = 17_280;
const PERSIST_TTL: u32 = DAY_LEDGERS * 90;
const PERSIST_THRESHOLD: u32 = DAY_LEDGERS * 30;

#[contract]
pub struct VeilproofRegistry;

#[contractimpl]
impl VeilproofRegistry {
    /// Constructs the registry with its admin, its fixed verifying key, and
    /// the grace window (seconds) during which a superseded root stays valid.
    ///
    /// The verifying key is fixed here and never updatable: a different
    /// circuit needs a different key and is a new deployment. This is the
    /// simplest, safest MVP choice — stated plainly so no one expects to
    /// rotate the circuit in place.
    pub fn __constructor(env: Env, admin: Address, vk: VerifyingKey, grace_seconds: u64) {
        if vk.ic.len() != EXPECTED_IC_LEN {
            panic_with_error!(&env, Error::MalformedVk);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Vk, &vk);
        env.storage()
            .instance()
            .set(&DataKey::Grace, &grace_seconds);
    }

    /// Admin authorizes `issuer` to publish roots under `credential`.
    pub fn register_issuer(
        env: Env,
        admin: Address,
        issuer: Address,
        credential: Symbol,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let key = DataKey::Issuer(credential.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::IssuerExists);
        }
        env.storage().persistent().set(
            &key,
            &IssuerConfig {
                issuer: issuer.clone(),
                active: true,
            },
        );
        bump(&env, &key);
        IssuerRegistered { credential, issuer }.publish(&env);
        Ok(())
    }

    /// Admin deactivates the issuer for `credential`. Existing roots remain
    /// readable, but no new roots may be published until re-registered.
    pub fn revoke_issuer(env: Env, admin: Address, credential: Symbol) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let key = DataKey::Issuer(credential.clone());
        let mut cfg: IssuerConfig = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::IssuerNotFound)?;
        cfg.active = false;
        env.storage().persistent().set(&key, &cfg);
        bump(&env, &key);
        IssuerRevoked { credential }.publish(&env);
        Ok(())
    }

    /// An authorized, active issuer publishes (or updates) the Merkle root
    /// for its credential. The prior root is retained for the grace window.
    pub fn publish_root(
        env: Env,
        issuer: Address,
        credential: Symbol,
        merkle_root: BytesN<32>,
    ) -> Result<(), Error> {
        let key = DataKey::Issuer(credential.clone());
        let cfg: IssuerConfig = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::IssuerNotFound)?;
        if !cfg.active || cfg.issuer != issuer {
            return Err(Error::NotIssuer);
        }
        issuer.require_auth();

        let now = env.ledger().timestamp();
        let roots_key = DataKey::Roots(credential.clone());
        let history = match env.storage().persistent().get::<_, RootHistory>(&roots_key) {
            Some(prev) => RootHistory {
                current: merkle_root.clone(),
                current_ts: now,
                previous: Some(prev.current),
                previous_ts: prev.current_ts,
            },
            None => RootHistory {
                current: merkle_root.clone(),
                current_ts: now,
                previous: None,
                previous_ts: 0,
            },
        };
        env.storage().persistent().set(&roots_key, &history);
        bump(&env, &roots_key);
        RootPublished {
            credential,
            root: merkle_root,
        }
        .publish(&env);
        Ok(())
    }

    /// Verifies a holder's membership proof and, on success, records the
    /// holder as verified for the credential and burns the nullifier.
    ///
    /// The public inputs to the proof are (root, nullifier). The root is not
    /// taken from the caller — it is the issuer's current root, or the prior
    /// one while still within the grace window — so a proof cannot claim
    /// membership in a root the issuer never published. Passing the root as
    /// an argument would only invite it to disagree with storage.
    pub fn verify_credential(
        env: Env,
        holder: Address,
        credential: Symbol,
        proof: Proof,
        nullifier: BytesN<32>,
    ) -> Result<(), Error> {
        holder.require_auth();

        let vk: VerifyingKey = env
            .storage()
            .instance()
            .get(&DataKey::Vk)
            .ok_or(Error::NotInitialized)?;
        let history: RootHistory = env
            .storage()
            .persistent()
            .get(&DataKey::Roots(credential.clone()))
            .ok_or(Error::NoRoot)?;

        // Replay check first — cheaper than a pairing, and decisive.
        let null_key = DataKey::Nullifier(NullifierKey {
            credential: credential.clone(),
            nullifier: nullifier.clone(),
        });
        if env.storage().persistent().has(&null_key) {
            return Err(Error::NullifierUsed);
        }

        // Try the current root; if that isn't the root the holder proved
        // against, try the previous one while it is still within grace.
        let mut ok = groth16_verify(&env, &vk, &proof, &history.current, &nullifier)?;
        if !ok {
            if let Some(previous) = history.previous {
                let grace: u64 = env.storage().instance().get(&DataKey::Grace).unwrap_or(0);
                let now = env.ledger().timestamp();
                if now <= history.previous_ts.saturating_add(grace) {
                    ok = groth16_verify(&env, &vk, &proof, &previous, &nullifier)?;
                }
            }
        }
        if !ok {
            return Err(Error::ProofInvalid);
        }

        // Burn the nullifier and record the verification. Order matters: the
        // nullifier is recorded so the same credential can never verify again,
        // even under a different holder address.
        env.storage().persistent().set(&null_key, &true);
        bump(&env, &null_key);

        let now = env.ledger().timestamp();
        let verified_key = DataKey::Verified(VerifiedKey {
            holder: holder.clone(),
            credential: credential.clone(),
        });
        env.storage().persistent().set(&verified_key, &now);
        bump(&env, &verified_key);

        CredentialVerified {
            credential,
            holder,
            timestamp: now,
        }
        .publish(&env);
        Ok(())
    }

    // --- views ---------------------------------------------------------

    pub fn is_verified(env: Env, holder: Address, credential: Symbol) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Verified(VerifiedKey { holder, credential }))
    }

    /// Batch form of [`Self::is_verified`]: one bool per holder, in the same
    /// order. Bounded by [`MAX_BATCH`] so a single call cannot exhaust the
    /// read budget; a larger query is rejected rather than truncated.
    pub fn are_verified(
        env: Env,
        holders: Vec<Address>,
        credential: Symbol,
    ) -> Result<Vec<bool>, Error> {
        if holders.len() > MAX_BATCH {
            return Err(Error::BatchTooLarge);
        }
        let mut out = Vec::new(&env);
        for holder in holders.iter() {
            out.push_back(
                env.storage()
                    .persistent()
                    .has(&DataKey::Verified(VerifiedKey {
                        holder,
                        credential: credential.clone(),
                    })),
            );
        }
        Ok(out)
    }

    pub fn verified_at(env: Env, holder: Address, credential: Symbol) -> Option<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::Verified(VerifiedKey { holder, credential }))
    }

    pub fn is_nullifier_used(env: Env, credential: Symbol, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(NullifierKey {
                credential,
                nullifier,
            }))
    }

    pub fn current_root(env: Env, credential: Symbol) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get::<_, RootHistory>(&DataKey::Roots(credential))
            .map(|h| h.current)
    }

    pub fn issuer_of(env: Env, credential: Symbol) -> Option<Address> {
        env.storage()
            .persistent()
            .get::<_, IssuerConfig>(&DataKey::Issuer(credential))
            .map(|c| c.issuer)
    }

    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    // --- internal ------------------------------------------------------

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if *admin != stored {
            return Err(Error::NotAdmin);
        }
        admin.require_auth();
        Ok(())
    }
}

/// Verifies a Groth16 proof for the fixed (root, nullifier) circuit against
/// one candidate root, using the native BN254 pairing check.
///
/// The verification equation, with `vk_x = IC[0] + root·IC[1] + nullifier·IC[2]`:
///
///   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
///
/// which is arkworks' `e(A,B) = e(alpha,beta)·e(vk_x,gamma)·e(C,delta)` moved
/// to one side, negating A only. Points and scalars use the CAP-0074
/// encoding described in types.rs and the README.
fn groth16_verify(
    env: &Env,
    vk: &VerifyingKey,
    proof: &Proof,
    root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Result<bool, Error> {
    if vk.ic.len() != EXPECTED_IC_LEN {
        return Err(Error::MalformedVk);
    }
    let bn = env.crypto().bn254();

    let a = Bn254G1Affine::from_bytes(proof.a.clone());
    let c = Bn254G1Affine::from_bytes(proof.c.clone());

    // vk_x = IC[0] + root·IC[1] + nullifier·IC[2]
    let ic0 = Bn254G1Affine::from_bytes(vk.ic.get(0).unwrap());
    let ic1 = Bn254G1Affine::from_bytes(vk.ic.get(1).unwrap());
    let ic2 = Bn254G1Affine::from_bytes(vk.ic.get(2).unwrap());
    let root_s = scalar_be(env, root);
    let null_s = scalar_be(env, nullifier);
    let vk_x = bn.g1_add(
        &bn.g1_add(&ic0, &bn.g1_mul(&ic1, &root_s)),
        &bn.g1_mul(&ic2, &null_s),
    );

    // -A = (X, -Y), via the SDK's native G1 negation.
    let neg_a = -a;

    let alpha = Bn254G1Affine::from_bytes(vk.alpha_g1.clone());
    let beta = Bn254G2Affine::from_bytes(vk.beta_g2.clone());
    let gamma = Bn254G2Affine::from_bytes(vk.gamma_g2.clone());
    let delta = Bn254G2Affine::from_bytes(vk.delta_g2.clone());
    let b = Bn254G2Affine::from_bytes(proof.b.clone());

    let vp1 = vec![env, neg_a, alpha, vk_x, c];
    let vp2 = vec![env, b, beta, gamma, delta];
    Ok(bn.pairing_check(vp1, vp2))
}

/// A 32-byte big-endian scalar (CAP-0074 field encoding) as a Bn254Fr.
fn scalar_be(env: &Env, b: &BytesN<32>) -> Fr {
    let bytes = Bytes::from_array(env, &b.to_array());
    Fr::from_u256(U256::from_be_bytes(env, &bytes))
}

fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, PERSIST_THRESHOLD, PERSIST_TTL);
}
