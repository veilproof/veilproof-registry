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
    contract, contractimpl, vec, Address, Bytes, BytesN, Env, String, Symbol, Vec, U256,
};

use types::{
    AdminChanged, AdminProposed, CircuitPaused, CircuitRegistered, CircuitUnpaused,
    CredentialVerified, DataKey, Error, IssuerConfig, IssuerRegistered, IssuerRevoked,
    IssuerRotated, NullifierKey, OpenRegistrationSet, Proof, RootHistory, RootPublished,
    VerifiedKey, VerifyingKey,
};

/// Public inputs for the fixed circuit are (root, nullifier, addr), so the IC
/// vector has one constant term plus three, i.e. length 4.
const EXPECTED_IC_LEN: u32 = 4;

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
    /// Constructs the registry with its admin and the grace window (seconds)
    /// during which a superseded root stays valid. Verifying keys are added
    /// afterwards with [`Self::register_circuit`].
    pub fn __constructor(env: Env, admin: Address, grace_seconds: u64) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Grace, &grace_seconds);
        bump_instance(&env);
    }

    /// Admin offers the role to `new_admin`, who must call
    /// [`Self::accept_admin`] to take it. The current admin keeps every
    /// privilege until then, so a mistyped address costs nothing: propose again
    /// and the earlier offer is replaced.
    ///
    /// The handover is two-step because the failure it exists to prevent is
    /// losing the admin role, and a one-step transfer to an address nobody
    /// controls would do exactly that, permanently.
    pub fn propose_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        bump_instance(&env);
        AdminProposed {
            admin,
            proposed: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// The proposed address takes the admin role. The previous admin loses all
    /// privilege in the same call.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NotPendingAdmin)?;
        if pending != new_admin {
            return Err(Error::NotPendingAdmin);
        }
        new_admin.require_auth();

        let previous: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        bump_instance(&env);
        AdminChanged {
            previous,
            admin: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Admin registers a verifying key under a circuit name. Circuits are
    /// register-once: a name cannot be silently repointed at a different key
    /// (which would change what proofs verify). To upgrade a circuit, register
    /// it under a new name and point issuers at it.
    ///
    /// Every circuit shares the same public-input schema (root, nullifier,
    /// addr), so a new circuit can differ in tree depth, hash, or setup while
    /// the contract's verification logic stays identical.
    pub fn register_circuit(
        env: Env,
        admin: Address,
        circuit: Symbol,
        vk: VerifyingKey,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if vk.ic.len() != EXPECTED_IC_LEN {
            return Err(Error::MalformedVk);
        }
        let key = DataKey::Circuit(circuit.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::CircuitExists);
        }
        env.storage().persistent().set(&key, &vk);
        bump(&env, &key);
        CircuitRegistered { circuit }.publish(&env);
        Ok(())
    }

    /// Admin stops `verify_credential` for every credential on `circuit`. This
    /// is the response to a soundness bug: if a circuit's proofs can be forged,
    /// each new verification may be false. Existing statuses stay readable, so
    /// consumers do not break, and they can check `verified_at` against the time
    /// of the pause.
    ///
    /// Scoped to the circuit because that is what a soundness bug is scoped to:
    /// per-credential would need one call per issuer in an emergency, and a
    /// global switch would halt circuits that are not affected. Publishing roots
    /// stays open, since a root confers nothing without a proof.
    pub fn pause_circuit(env: Env, admin: Address, circuit: Symbol) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Circuit(circuit.clone()))
        {
            return Err(Error::CircuitNotFound);
        }
        let key = DataKey::Paused(circuit.clone());
        env.storage().persistent().set(&key, &true);
        bump(&env, &key);
        CircuitPaused { circuit }.publish(&env);
        Ok(())
    }

    /// Admin resumes verification for `circuit`.
    pub fn unpause_circuit(env: Env, admin: Address, circuit: Symbol) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Paused(circuit.clone()));
        CircuitUnpaused { circuit }.publish(&env);
        Ok(())
    }

    /// Admin authorizes `issuer` to publish roots under `credential`, whose
    /// proofs are checked against `circuit`'s verifying key.
    pub fn register_issuer(
        env: Env,
        admin: Address,
        issuer: Address,
        credential: Symbol,
        circuit: Symbol,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        Self::write_new_issuer(&env, issuer, credential, circuit)
    }

    /// Admin allows or stops self-service registration through
    /// [`Self::claim_credential`]. Closed by default, and meant for sandboxes
    /// such as the public testnet demo.
    pub fn set_open_registration(env: Env, admin: Address, open: bool) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::OpenRegistration, &open);
        bump_instance(&env);
        OpenRegistrationSet { open }.publish(&env);
        Ok(())
    }

    /// On a registry with open registration, `issuer` claims an unused
    /// credential name for itself, bound to an existing circuit.
    ///
    /// This changes what a credential means. On an open registry anyone can be
    /// an issuer, so `is_verified` says only that an address belongs to the set
    /// of whoever claimed that name: a consumer has to check `issuer_of` before
    /// trusting it. Circuits remain admin-curated, as does the ability to revoke.
    pub fn claim_credential(
        env: Env,
        issuer: Address,
        credential: Symbol,
        circuit: Symbol,
    ) -> Result<(), Error> {
        issuer.require_auth();
        let open: bool = env
            .storage()
            .instance()
            .get(&DataKey::OpenRegistration)
            .unwrap_or(false);
        if !open {
            return Err(Error::RegistrationClosed);
        }
        Self::write_new_issuer(&env, issuer, credential, circuit)
    }

    /// Admin replaces the issuer for `credential` with `new_issuer`, which also
    /// reactivates a revoked credential. Published roots and verified holders
    /// are untouched, so nobody has to re-verify over an operational event.
    ///
    /// Admin-only: rotation is the response to a compromised issuer key, and an
    /// attacker holding that key must not be able to rotate it to themselves.
    /// A root the old key published stays valid until the new issuer replaces
    /// it, so after a compromise the new issuer should publish straight away.
    pub fn rotate_issuer(
        env: Env,
        admin: Address,
        credential: Symbol,
        new_issuer: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let key = DataKey::Issuer(credential.clone());
        let mut cfg: IssuerConfig = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::IssuerNotFound)?;
        let previous = cfg.issuer;
        cfg.issuer = new_issuer.clone();
        cfg.active = true;
        env.storage().persistent().set(&key, &cfg);
        bump(&env, &key);
        IssuerRotated {
            credential,
            previous,
            issuer: new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Admin deactivates the issuer for `credential`. Existing roots remain
    /// readable and proofs against them still verify, but no new roots may be
    /// published until [`Self::rotate_issuer`] names an issuer again.
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
                previous_ts: now,
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
        bump(&env, &key);
        bump_instance(&env);
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
    /// The public inputs to the proof are (root, nullifier, addr). The root is not
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

        // Resolve the credential's issuer config, then the verifying key for
        // its circuit. A credential with no issuer has no circuit either.
        let issuer_key = DataKey::Issuer(credential.clone());
        let cfg: IssuerConfig = env
            .storage()
            .persistent()
            .get(&issuer_key)
            .ok_or(Error::IssuerNotFound)?;
        if env
            .storage()
            .persistent()
            .has(&DataKey::Paused(cfg.circuit.clone()))
        {
            return Err(Error::CircuitPaused);
        }
        let circuit_key = DataKey::Circuit(cfg.circuit.clone());
        let vk: VerifyingKey = env
            .storage()
            .persistent()
            .get(&circuit_key)
            .ok_or(Error::CircuitNotFound)?;
        let roots_key = DataKey::Roots(credential.clone());
        let history: RootHistory = env
            .storage()
            .persistent()
            .get(&roots_key)
            .ok_or(Error::NoRoot)?;

        // Replay check first — cheaper than a pairing, and decisive.
        let null_key = DataKey::Nullifier(NullifierKey {
            credential: credential.clone(),
            nullifier: nullifier.clone(),
        });
        if env.storage().persistent().has(&null_key) {
            return Err(Error::NullifierUsed);
        }

        // The proof is bound to the holder's address: it carries `addr` as a
        // public input, derived here from the caller. A proof made for one
        // holder therefore cannot be replayed by another — a different caller
        // yields a different `addr` and the pairing check fails.
        let addr = address_field(&env, &holder);

        // Try the current root; if that isn't the root the holder proved
        // against, try the previous one while it is still within grace.
        let mut ok = groth16_verify(&env, &vk, &proof, &history.current, &nullifier, &addr)?;
        if !ok {
            if let Some(previous) = history.previous {
                let grace: u64 = env.storage().instance().get(&DataKey::Grace).unwrap_or(0);
                let now = env.ledger().timestamp();
                if now <= history.previous_ts.saturating_add(grace) {
                    ok = groth16_verify(&env, &vk, &proof, &previous, &nullifier, &addr)?;
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

        // Everything verification depends on stays alive while it is in use.
        bump(&env, &issuer_key);
        bump(&env, &circuit_key);
        bump(&env, &roots_key);
        bump_instance(&env);

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

    /// The circuit a credential's proofs are verified against, if registered.
    pub fn circuit_of(env: Env, credential: Symbol) -> Option<Symbol> {
        env.storage()
            .persistent()
            .get::<_, IssuerConfig>(&DataKey::Issuer(credential))
            .map(|c| c.circuit)
    }

    /// Whether a circuit name has a registered verifying key.
    pub fn has_circuit(env: Env, circuit: Symbol) -> bool {
        env.storage().persistent().has(&DataKey::Circuit(circuit))
    }

    /// Whether the admin has paused verification for a circuit.
    pub fn is_circuit_paused(env: Env, circuit: Symbol) -> bool {
        env.storage().persistent().has(&DataKey::Paused(circuit))
    }

    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Whether anyone may claim an unused credential name.
    pub fn open_registration(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::OpenRegistration)
            .unwrap_or(false)
    }

    /// The address offered the admin role and yet to accept it, if any.
    pub fn pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    // --- internal ------------------------------------------------------

    fn write_new_issuer(
        env: &Env,
        issuer: Address,
        credential: Symbol,
        circuit: Symbol,
    ) -> Result<(), Error> {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Circuit(circuit.clone()))
        {
            return Err(Error::CircuitNotFound);
        }
        let key = DataKey::Issuer(credential.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::IssuerExists);
        }
        env.storage().persistent().set(
            &key,
            &IssuerConfig {
                issuer: issuer.clone(),
                active: true,
                circuit,
            },
        );
        bump(env, &key);
        IssuerRegistered { credential, issuer }.publish(env);
        Ok(())
    }

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

/// Verifies a Groth16 proof with public inputs (root, nullifier, addr) against
/// one candidate root, using the native BN254 pairing check.
///
/// The verification equation, with
/// `vk_x = IC[0] + root·IC[1] + nullifier·IC[2] + addr·IC[3]`:
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
    addr: &Fr,
) -> Result<bool, Error> {
    if vk.ic.len() != EXPECTED_IC_LEN {
        return Err(Error::MalformedVk);
    }
    let bn = env.crypto().bn254();

    let a = Bn254G1Affine::from_bytes(proof.a.clone());
    let c = Bn254G1Affine::from_bytes(proof.c.clone());

    // vk_x = IC[0] + root·IC[1] + nullifier·IC[2] + addr·IC[3]
    let ic0 = Bn254G1Affine::from_bytes(vk.ic.get(0).unwrap());
    let ic1 = Bn254G1Affine::from_bytes(vk.ic.get(1).unwrap());
    let ic2 = Bn254G1Affine::from_bytes(vk.ic.get(2).unwrap());
    let ic3 = Bn254G1Affine::from_bytes(vk.ic.get(3).unwrap());
    let root_s = scalar_be(env, root);
    let null_s = scalar_be(env, nullifier);
    let mut vk_x = bn.g1_add(&ic0, &bn.g1_mul(&ic1, &root_s));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic2, &null_s));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic3, addr));

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

/// Bind an address to a scalar: `Fr(sha256(strkey) mod r)`, over the same
/// strkey bytes `holder.to_string()` produces. veilproof-server derives the
/// identical value off-chain, so a proof only verifies for its intended holder.
fn address_field(env: &Env, holder: &Address) -> Fr {
    let s: String = holder.to_string();
    let len = s.len() as usize;
    // Stellar strkeys are 56 chars (accounts, contracts) or 69 (muxed); 128 is
    // ample headroom.
    let mut buf = [0u8; 128];
    s.copy_into_slice(&mut buf[..len]);
    let bytes = Bytes::from_slice(env, &buf[..len]);
    let hash = env.crypto().sha256(&bytes);
    scalar_be(env, &hash.to_bytes())
}

fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, PERSIST_THRESHOLD, PERSIST_TTL);
}

/// Extend the contract instance (and with it the admin and grace values) along
/// with its code. Nothing else does this: without it a registry in daily use
/// would still lapse once its instance TTL ran out.
fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(PERSIST_THRESHOLD, PERSIST_TTL);
}
