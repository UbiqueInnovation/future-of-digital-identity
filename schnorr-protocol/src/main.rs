use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{thread_rng, Rng};

fn main() {
    let mut rng = thread_rng();
    let (g, h) = (
        RistrettoPoint::random(&mut rng),
        RistrettoPoint::random(&mut rng),
    );
    println!("We create a random link secret");
    let secret = Scalar::random(&mut rng);
    println!("And commit to it");
    let (c, opening) = create_commitment(secret, &g, &h);

    println!("The proofer constructs the proof base with randomly chosen values");
    let (proof_base, a1, a2) = schnorr_phase1(&g, &h);

    println!("and sends it to the verifier");
    println!("P (proof_base) ------> V");
    println!("The verifier saves the proof base and sends a challenge back");
    let (proof_base, challenge) = schnorr_phase2(proof_base);
    println!("P <------ (challenge) V");
    println!("The proofer uses the challenge and calculates s1 and s2");
    let schnorr_signature = schnorr_phase3(a1, a2, &challenge, &opening.0, &opening.1);
    println!(
        "The proofer now sends the two scalars back to the verifier, who now can verify the ZKP"
    );
    println!("P (s1,s2) ------> V");
    println!(
        "The proofer has knowledge of the secret AND the blinding: {}",
        schnorr_verify(&g, &h, &challenge, &c, &schnorr_signature, proof_base)
    );

}


struct Commitment {
    commitment: RistrettoPoint,
    g: RistrettoPoint,
    h: RistrettoPoint,
}
type Opening = (Scalar, Scalar);
type SchnorrSignature = (Scalar, Scalar);

/// In the first phase of the Schnorr protocol we generate two random values
/// in order to prove the knowledge of secret value and blinding factor
/// This step is done by the proofer
///
fn schnorr_phase1(g: &RistrettoPoint, h: &RistrettoPoint) -> (RistrettoPoint, Scalar, Scalar) {
    let mut rng = thread_rng();
    let a1: Scalar = rng.gen::<u32>().into();
    let a2: Scalar = rng.gen::<u32>().into();
    (a1 * g + a2 * h, a1, a2)
}

/// In the second phase, the verifier "saves" the proof base and calculates a random
/// challenge. This challenge is send back to the proofer
fn schnorr_phase2(proof_base: RistrettoPoint) -> (RistrettoPoint, Scalar) {
    let mut rng = thread_rng();
    let challenge: Scalar = rng.gen::<u32>().into();
    (proof_base, challenge)
}
/// In the third phase the proofer uses the random challenge and calculates
/// the "s" values such that the verifier can check the proof.
/// By using the same challenge, we logically AND the knowledge of the two
/// discrete logarithm (secret and blinding).
fn schnorr_phase3(
    a1: Scalar,
    a2: Scalar,
    challenge: &Scalar,
    secret: &Scalar,
    blinding: &Scalar,
) -> SchnorrSignature {
    let s1 = a1 - challenge * secret;
    let s2 = a2 - challenge * blinding;
    (s1, s2)
}

/// We have all setup to actually verify the zero knowledge proof
fn schnorr_verify(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    challenge: &Scalar,
    commitment: &Commitment,
    signature: &SchnorrSignature,
    proof_base: RistrettoPoint,
) -> bool {
    let prime = signature.0 * g + signature.1 * h + challenge * commitment.commitment;
    prime == proof_base
}

/// Create a commitment based on a secret value
/// Returns the Commitment with the public generators g and h, as well
/// as the opening to the commitment as a tuple (secret, blinding)
fn create_commitment(
    secret: Scalar,
    g: &RistrettoPoint,
    h: &RistrettoPoint,
) -> (Commitment, Opening) {
    let mut rng = thread_rng();

    let blinding = Scalar::random(&mut rng);
    let commitment = secret * g + blinding * h;

    (
        Commitment {
            commitment,
            g: *g,
            h: *h,
        },
        (secret, blinding),
    )
}
