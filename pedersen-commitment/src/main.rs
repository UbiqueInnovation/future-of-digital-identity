use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{rngs::OsRng, thread_rng, Rng};

fn main() {
    let mut rng = thread_rng();

    println!("Jenny chooses a winning car in the interval [0,10]");
    let jenny_secret: u32 = rng.gen_range(0u32, 5u32);

    println!("So does Tomas");
    let tomas_secret: u32 = rng.gen_range(0u32, 5u32);
    println!("Generate a public key for the event");
    let (g, h) = (
        RistrettoPoint::random(&mut rng),
        RistrettoPoint::random(&mut rng),
    );
    println!("Now both parties commit their secret value");
    let (jenny_commitment, jenny_opening) = create_commitment(jenny_secret.into(), &g, &h);
    let (tomas_commitment, tomas_opening) = create_commitment(tomas_secret.into(), &g, &h);

    println!("Since the event is very short term, both agree to reveal their blinding factor to the almighty narrator");
    let diff_blinding = jenny_opening.1 - tomas_opening.1;
    println!("With this we can abort if the commitments are for the same secret");
    if same_commitment(&jenny_commitment, &tomas_commitment, &diff_blinding) {
        println!("It is a commitment to the same value");
        return;
    }

    let winning_car: u32 = rng.gen_range(0u32, 5u32);
    println!("Car number {} won", winning_car);
    println!("Jenny reveals her commitment: ({})", jenny_secret); // we use here the u32 value we calculated, otherwise we'd need to convert back from the base field of the curve to the unsigned integers
    println!("Tomas reveals his commitment: ({})", tomas_secret);

    // If jenny claims to have won, and her commitment is true, she actually wins
    if winning_car == jenny_secret && verify_commitment(&jenny_commitment, &jenny_opening) {
        println!("Jenny won");
    } else if winning_car == tomas_secret && verify_commitment(&tomas_commitment, &tomas_opening) {
        println!("Tomas won");
    }
}

struct Commitment {
    commitment: RistrettoPoint,
    g: RistrettoPoint,
    h: RistrettoPoint,
}
type Opening = (Scalar, Scalar);
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
            g: g.clone(),
            h: h.clone(),
        },
        (secret, blinding),
    )
}
/// Verify the commitment assuming honesty, and using the public generators inside
/// the Commitment struct, together with the opening. In theory on would fetch g and h from a ledger, or instruct
/// Jenny and Tomas to use the specified key.
fn verify_commitment(commitment: &Commitment, opening: &Opening) -> bool {
    // in a real case scenario, Jenny resp. Tomas public key would be on something like a ledger
    // Here we assume a certain honesty of both
    let c_prime = commitment.g * opening.0 + commitment.h * opening.1;
    commitment.commitment == c_prime
}

/// Verify the equality of the commitments c1 and c2, given the difference of the blindings
fn same_commitment(c1: &Commitment, c2: &Commitment, diff_opening: &Scalar) -> bool {
    let diff = c1.commitment - c2.commitment;
    assert_eq!(c1.g, c2.g);
    assert_eq!(c1.h, c2.h);
    diff == diff_opening * c1.h
}
