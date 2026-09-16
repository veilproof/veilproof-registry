use soroban_sdk::{contracterror, contractevent, contracttype, Address, BytesN, Symbol, Vec};

/// A Groth16 proof over BN254, in Soroban's native encoding (CAP-0074):
/// G1 points are 64 uncompressed big-endian bytes, G2 points are 128, with
/// Fp2 coordinates ordered c1 then c0. See the README's "BN254 Encoding
/// Notes" — these byte layouts are the crux of correctness.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    /// G1: be(X) || be(Y).
    pub a: BytesN<64>,
    /// G2: be(X.c1) || be(X.c0) || be(Y.c1) || be(Y.c0).
    pub b: BytesN<128>,
    /// G1.
    pub c: BytesN<64>,
}

/// The Groth16 verifying key for the one fixed circuit this contract knows
/// (Merkle-membership + nullifier). Fixed at contract construction and never
/// updatable: a different circuit is a different verifying key and a breaking
/// change that requires a new deployment. See the README trust model.
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha_g1: BytesN<64>,
    pub beta_g2: BytesN<128>,
    pub gamma_g2: BytesN<128>,
    pub delta_g2: BytesN<128>,
    /// gamma_abc_g1 / "IC": one G1 point per public input, plus a leading
    /// constant term. For this circuit the public inputs are (root,
    /// nullifier), so `ic` has length 3.
    pub ic: Vec<BytesN<64>>,
}

/// Which address may publish roots for a named credential, and whether that
/// authorization is currently active.
#[contracttype]
#[derive(Clone)]
pub struct IssuerConfig {
    pub issuer: Address,
    pub active: bool,
}

/// The current Merkle root for a credential and the immediately previous one.
///
/// Only one prior root is retained, valid until `previous_ts + grace`. A
/// holder can generate a proof against a root that the issuer supersedes
/// before the holder submits; the grace window lets that proof still verify
/// for a bounded time. Keeping only one previous root bounds storage and the
/// verification work per call (at most two pairing checks).
#[contracttype]
#[derive(Clone)]
pub struct RootHistory {
    pub current: BytesN<32>,
    pub current_ts: u64,
    pub previous: Option<BytesN<32>>,
    pub previous_ts: u64,
}

/// Composite key for a used nullifier: scoped per credential, so the same
/// underlying leaf verified under two different credential types is two
/// distinct nullifiers and not a false collision.
#[contracttype]
#[derive(Clone)]
pub struct NullifierKey {
    pub credential: Symbol,
    pub nullifier: BytesN<32>,
}

/// Composite key for a holder's verification record.
#[contracttype]
#[derive(Clone)]
pub struct VerifiedKey {
    pub holder: Address,
    pub credential: Symbol,
}

#[contracttype]
pub enum DataKey {
    /// Admin address. Instance storage.
    Admin,
    /// The fixed verifying key. Instance storage.
    Vk,
    /// Grace window in seconds for a superseded root. Instance storage.
    Grace,
    /// credential_name -> IssuerConfig. Persistent.
    Issuer(Symbol),
    /// credential_name -> RootHistory. Persistent.
    Roots(Symbol),
    /// Used-nullifier marker. Persistent — must not silently expire, or
    /// replay protection is lost. See the README storage-TTL notes.
    Nullifier(NullifierKey),
    /// holder+credential -> unix timestamp of verification. Persistent.
    Verified(VerifiedKey),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The contract has not been constructed with a verifying key.
    NotInitialized = 1,
    /// The caller is not the admin.
    NotAdmin = 2,
    /// The caller is not the authorized, active issuer for this credential.
    NotIssuer = 3,
    /// An issuer is already registered for this credential name.
    IssuerExists = 4,
    /// No issuer is registered for this credential name.
    IssuerNotFound = 5,
    /// No root has been published for this credential name.
    NoRoot = 6,
    /// The proof did not verify against the current or any in-grace root.
    ProofInvalid = 7,
    /// The nullifier has already been used for this credential — replay.
    NullifierUsed = 8,
    /// The verifying key's IC length does not match the expected public-input count.
    MalformedVk = 9,
    /// A batch query exceeded the maximum allowed size.
    BatchTooLarge = 10,
}

// --- events ---------------------------------------------------------------

/// An issuer was authorized for a credential.
#[contractevent(topics = ["issuer"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRegistered {
    #[topic]
    pub credential: Symbol,
    pub issuer: Address,
}

/// An issuer was deactivated for a credential.
#[contractevent(topics = ["revoked"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRevoked {
    #[topic]
    pub credential: Symbol,
}

/// A new Merkle root was published for a credential.
#[contractevent(topics = ["root"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPublished {
    #[topic]
    pub credential: Symbol,
    pub root: BytesN<32>,
}

/// A holder was verified for a credential.
#[contractevent(topics = ["verified"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialVerified {
    #[topic]
    pub credential: Symbol,
    pub holder: Address,
    pub timestamp: u64,
}
