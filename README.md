# Zero Knowledge Proof Implementation

This project demonstrates a basic implementation of the Schnorr Protocol, which is a type of Zero Knowledge Proof (ZKP) system. The implementation shows how a prover can convince a verifier that they know a discrete logarithm without revealing the actual value.

## Concept

In this implementation:
1. The prover knows a secret value x
2. The public value y = g^x mod p is known to everyone
3. The prover wants to prove they know x without revealing it

The protocol works as follows:

1. The prover generates a random value r and sends t = g^r mod p to the verifier
2. The verifier generates a random challenge c
3. The prover computes s = r + c*x mod (p-1)
4. The verifier checks if g^s = t * y^c mod p

## Running the Project

To run the demonstration:

```bash
cargo run
```

## Implementation Details

- Uses small numbers for demonstration purposes
- In a real implementation, you would use cryptographically secure parameters
- The implementation uses the following Rust crates:
  - `num-bigint` for big integer arithmetic
  - `rand` for random number generation
  - `sha2` for challenge generation

## Security Note

This is a demonstration implementation and uses small numbers for readability. In a production environment, you would need to:

1. Use cryptographically secure parameters
2. Use proper random number generation
3. Implement proper error handling
4. Use constant-time operations to prevent timing attacks

## References

This implementation is based on the Schnorr Protocol, a fundamental zero-knowledge proof system that demonstrates the principles outlined in various academic papers on zero-knowledge proofs. 

* Original Paper [link](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf)
* Zero Knowledge used for Nuclear Warhead verification [link](https://www.nature.com/articles/ncomms12890)
