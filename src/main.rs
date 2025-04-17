use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use sha2::{Sha256, Digest};

/// Represents the public parameters for the Schnorr protocol
#[derive(Clone)]
struct PublicParams {
    p: BigUint, // A prime number
    q: BigUint, // A prime factor of p-1
    g: BigUint, // A generator of the subgroup of order q
}

/// Represents a prover who knows the secret
struct Prover {
    params: PublicParams,
    x: BigUint,     // The secret (private key)
    y: BigUint,     // The public commitment (public key)
}

/// Represents a verifier who wants to be convinced
struct Verifier {
    params: PublicParams,
}

impl PublicParams {
    fn new() -> Self {
        println!("Generating parameters for demonstration...");
        
        // Using small primes for demonstration
        // q = 11 (a prime number)
        // p = 2q + 1 = 23 (also prime)
        let q = BigUint::from(11u32);
        let p = BigUint::from(23u32);
        
        // g = 4 is a generator of the subgroup of order 11 in Z_23
        let g = BigUint::from(4u32);
        
        println!("Parameters generated:");
        println!("p = {}", p);
        println!("q = {}", q);
        println!("g = {}", g);
        
        PublicParams { p, q, g }
    }
}

impl Prover {
    fn new(params: PublicParams, secret: BigUint) -> Self {
        // Ensure secret is in the correct range (0 < x < q)
        let x = secret % &params.q;
        let y = params.g.modpow(&x, &params.p);
        Prover {
            params,
            x,
            y,
        }
    }

    fn step1(&self) -> (BigUint, BigUint) {
        let mut rng = thread_rng();
        // Generate random r in [1, q-1]
        let r = rng.gen_biguint_below(&self.params.q);
        // Calculate commitment t = g^r mod p
        let t = self.params.g.modpow(&r, &self.params.p);
        (r, t)
    }

    fn step3(&self, r: &BigUint, c: &BigUint) -> BigUint {
        // Calculate response s = (r + c*x) mod q
        (r + (c * &self.x)) % &self.params.q
    }
}

impl Verifier {
    fn new(params: PublicParams) -> Self {
        Verifier { params }
    }

    fn step2(&self, t: &BigUint, y: &BigUint) -> BigUint {
        let mut hasher = Sha256::new();
        hasher.update(t.to_bytes_be());
        hasher.update(y.to_bytes_be());
        let result = hasher.finalize();
        BigUint::from_bytes_be(&result) % &self.params.q
    }

    fn verify(&self, t: &BigUint, c: &BigUint, s: &BigUint, y: &BigUint) -> bool {
        // Verify that g^s = t * y^c (mod p)
        let left = self.params.g.modpow(s, &self.params.p);
        let right = (t * y.modpow(c, &self.params.p)) % &self.params.p;
        left == right
    }
}

fn main() {
    // Set up the system with demonstration parameters
    let params = PublicParams::new();
    
    // Create a prover with a secret value
    let secret = BigUint::from(6u32);  // The secret we want to prove knowledge of
    let prover = Prover::new(params.clone(), secret);
    
    // Create a verifier
    let verifier = Verifier::new(params);
    
    println!("\nStarting Zero Knowledge Proof demonstration...");
    println!("Prover knows x such that y = g^x mod p");
    println!("Public key y = {}", prover.y);
    
    // Step 1: Prover creates commitment
    let (r, t) = prover.step1();
    println!("\nStep 1: Prover generates random commitment t = {}", t);
    
    // Step 2: Verifier creates challenge
    let c = verifier.step2(&t, &prover.y);
    println!("Step 2: Verifier generates challenge c = {}", c);
    
    // Step 3: Prover responds to challenge
    let s = prover.step3(&r, &c);
    println!("Step 3: Prover generates response s = {}", s);
    
    // Step 4: Verifier checks the proof
    let valid = verifier.verify(&t, &c, &s, &prover.y);
    println!("\nVerification result: {}", if valid { "ACCEPTED ✓" } else { "REJECTED ✗" });
    
    if valid {
        println!("\nThe prover has successfully demonstrated knowledge of the secret");
        println!("Secret value used (for demonstration): x = {}", prover.x);
    }
}
