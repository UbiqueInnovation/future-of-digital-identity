use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
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

    println!();
    println!("We can also prove a relation between the logarithms");
    println!("We will now prove that 4*x1 = x2 AND that we know x1 and x2");
    let x1: Scalar = 21u32.into();
    let x2: Scalar = 84u32.into();

    println!("Let's create the commitments");
    let (c1, opening1) = create_commitment(x1, &g, &h);
    let (c2, opening2) = create_commitment(x2, &g, &h);

    println!("In our simple multiple case, we define a relation which gives us the multiple of the argument");
    println!("In our concrete case, we want to proof that x2 is 4 times x1");
    let four: Scalar = 4u32.into();
    let the_relation = |s| four * s;

    println!(
        "By using the relation we make sure that our 'random' values fulfill the relation as well"
    );
    let (proof_base1, proof_base2, a1, r1, a2, r2) = schnorr_phase1_relation(&g, &h, the_relation);
    println!("As usual we get a challenge in exchange to the base points (which are now the TWO commitments)");
    let (proof_base1, proof_base2, challenge) = schnorr_phase2_relation(proof_base1, proof_base2);

    println!("We now calculate the 'Schnorr-Signature' for both commitments");
    let (s1, s2) = schnorr_phase3_relation(a1, r1, a2, r2, &challenge, &opening1, &opening2);
    
    println!(
        "We first verify the knowledge of both logarithms, by checking both schnorr signatures s1 and s2"
    );
    println!("Note the following");
    println!(r#"-4 * s1 + s2 = -4 * a1  + 4 * challenge * x1 + a2 - challenge * x2"#);
    println!(r#"             = \______/ + \_________________/"#);
    println!(r#"                  |               |"#);
    println!(r#"             =   -a2 +     challenge * x2   + a2 - challenge * x2"#);
    println!(r#"             = 0"#);
    println!("Hence by checking the relation on s1 and s2 we can verify the relation");
    println!(
        "Relation is :{}",
        schnorr_verify_relation(
            &g,
            &h,
            &challenge,
            &c1,
            &c2,
            &s1,
            &s2,
            proof_base1,
            proof_base2,
            |s1, s2| -the_relation(1u32.into()) * s1 + s2,
            |s| { s == &Scalar::default() }
        )
    )
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

fn schnorr_phase1_relation<Relation>(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    relation: Relation,
) -> (
    RistrettoPoint,
    RistrettoPoint,
    Scalar,
    Scalar,
    Scalar,
    Scalar,
)
where
    Relation: Fn(Scalar) -> Scalar,
{
    let mut rng = thread_rng();
    let a1: Scalar = rng.gen::<u32>().into();
    let a2 = relation(a1);
    let r1: Scalar = rng.gen::<u32>().into();
    let r2 = relation(r1);
    (a1 * g + r1 * h, a2 * g + r2 * h, a1, r1, a2, r2)
}

/// In the second phase, the verifier "saves" the proof base and calculates a random
/// challenge. This challenge is send back to the proofer
fn schnorr_phase2(proof_base: RistrettoPoint) -> (RistrettoPoint, Scalar) {
    let mut rng = thread_rng();
    let challenge: Scalar = rng.gen::<u32>().into();
    (proof_base, challenge)
}
fn schnorr_phase2_relation(
    proof_base1: RistrettoPoint,
    proof_base2: RistrettoPoint,
) -> (RistrettoPoint, RistrettoPoint, Scalar) {
    let mut rng = thread_rng();
    let challenge: Scalar = rng.gen::<u32>().into();
    (proof_base1, proof_base2, challenge)
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
fn schnorr_phase3_relation(
    a1: Scalar,
    r1: Scalar,
    a2: Scalar,
    r2: Scalar,
    challenge: &Scalar,
    opening1: &Opening,
    opening2: &Opening,
) -> (SchnorrSignature, SchnorrSignature) {
    let sx1 = a1 - challenge * opening1.0;
    let sr1 = r1 - challenge * opening1.1;
    let sx2 = a2 - challenge * opening2.0;
    let sr2 = r2 - challenge * opening2.1;
    ((sx1, sr1), (sx2, sr2))
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

fn schnorr_verify_relation<Relation, System>(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    challenge: &Scalar,
    c1: &Commitment,
    c2: &Commitment,
    s1: &SchnorrSignature,
    s2: &SchnorrSignature,
    proof_base1: RistrettoPoint,
    proof_base2: RistrettoPoint,
    linear_system: System,
    relation: Relation,
) -> bool
where
    Relation: Fn(&Scalar) -> bool,
    System: Fn(&Scalar, &Scalar) -> Scalar,
{
    let c1_prime = s1.0 * g + s1.1 * h + challenge * c1.commitment;
    let c2_prime = s2.0 * g + s2.1 * h + challenge * c2.commitment;
    let quot = linear_system(&s1.0, &s2.0);
    println!("{}", c1_prime == proof_base1 && c2_prime == proof_base2);
    println!("{}", relation(&quot));
    c1_prime == proof_base1 && c2_prime == proof_base2 && relation(&quot)
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
