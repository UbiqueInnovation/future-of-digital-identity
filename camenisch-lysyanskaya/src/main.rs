use std::borrow::Cow;

use num_bigint_dig::{algorithms::mod_inverse, BigUint, RandBigInt, ToBigUint};

fn main() {
    camenisch_lysyanskaya();
}

fn camenisch_lysyanskaya() {
    let k = 200;
    let m = 200;
    let len_p_q = 2 * k;
    let mut p: BigUint = 0u32.into();
    let mut q: BigUint = 0u32.into();
    let mut rng = rand::thread_rng();
    println!("try finding primes");
    loop {
        if p == 0.to_biguint().unwrap() {
            let tmp_p = rng.gen_biguint(len_p_q);

            if is_safe_prime(&tmp_p) {
                println!("found p");
                p = tmp_p;
            }
        }
        if q == 0.to_biguint().unwrap() {
            let tmp_q = rng.gen_biguint(len_p_q);
            if is_safe_prime(&tmp_q) {
                println!("found q");
                q = tmp_q;
            }
        }
        if p != 0.to_biguint().unwrap() && q != 0.to_biguint().unwrap() {
            break;
        }
    }
    println!("Setup our public key");
    let n = &p * &q;
    let a_pre = rng.gen_biguint_below(&n);
    let a = (&a_pre * &a_pre) % &n;
    let a2_pre = rng.gen_biguint_below(&n);
    let a2 = (&a2_pre * &a2_pre) % &n;
    let b_pre = rng.gen_biguint_below(&n);
    let b = (&b_pre * &b_pre) % &n;
    let c_pre = rng.gen_biguint_below(&n);
    let c = (&c_pre * &c_pre) % &n;

    println!("Generated a1, a2, b and c");

    let s = rng.gen_biguint_range(&(2u32 * &n), &(3u32 * &n));
    let mut e = 0.to_biguint().unwrap();
    println!("Find a prime for e");
    loop {
        if e == 0.to_biguint().unwrap() {
            let tmp_e = rng.gen_biguint(m + 2);
            if is_prime(&tmp_e) {
                e = tmp_e;
                break;
            }
        }
    }
    // The origin of the wine
    let message = BigUint::from_bytes_be("Bordeaux".as_bytes());
    // The vintage of the wine
    let message2 = BigUint::from_bytes_be("1980".as_bytes());

    let phi = (p - 1u32) * (q - 1u32);
    println!("Using phi(n) we can invert e");
    let e_invert = mod_inverse(Cow::Borrowed(&e), Cow::Borrowed(&phi))
        .unwrap()
        .to_biguint()
        .unwrap();

    println!("Calculate the signature value for v by using the inverse of e");
    let v = (a.modpow(&message, &n) * a2.modpow(&message2, &n) * b.modpow(&s, &n) * &c)
        .modpow(&e_invert, &n)
        % &n;

    println!("Our signature {{s,e,v}} (full disclosure): ({},{},{})", s, e, v);

    println!("Calculate a commitment to the vintage of the wine");
    let C = a2.modpow(&message2, &n) * b.modpow(&(&s - 45u32), &n);
    println!(
        "Revealing all properties signature is correct: {}",
        v.modpow(&e, &n) % &n
            == (a.modpow(&message, &n) * a2.modpow(&message2, &n) * b.modpow(&s, &n) * &c) % &n
    );
    println!("Our signature {{s,e,v}} (only disclosing one property): ({},{},{})", 45, e, v);
    println!(
        "Revealing only the origin signature is correct: {}",
        v.modpow(&e, &n) % &n
            == (C * b.modpow(&(45u32.into()), &n) * a.modpow(&message, &n) * &c) % &n
    );
}

fn is_safe_prime(n: &BigUint) -> bool {
    is_prime(&((n - 1u32) / 2u32)) && is_prime(n)
}

fn is_prime(n: &BigUint) -> bool {
    miller_rabin(n, 100)
}

/// Apply the [miller rabin test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) to test for primeality
fn miller_rabin(p: &BigUint, rounds: usize) -> bool {
    let mut rng = rand::thread_rng();
    if p == &2u32.to_biguint().unwrap() {
        return true;
    }
    if p == &3u32.to_biguint().unwrap() {
        return true;
    }
    if p % 2u32 == 0u32.into() {
        return false;
    }
    let mut tmp_prime = p - 1u32;
    let mut r = 1;
    let mut d = 0u32.into();
    loop {
        tmp_prime /= 2u32;
        if &tmp_prime % 2u32 != 0.to_biguint().unwrap() {
            d = tmp_prime.clone();
            break;
        }
        r += 1;
    }
    'witness_loop: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&(2u32.into()), &(p - 2u32));
        let mut x = a.modpow(&d, p);
        if x == 1.to_biguint().unwrap() || x == (p - 1u32) {
            continue;
        }
        for j in 0..(r - 1) {
            x = x.modpow(&(2u32.into()), p);
            if x == (p - 1u32) {
                continue 'witness_loop;
            }
        }
        return false;
    }
    true
}
