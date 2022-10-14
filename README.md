# The Future of Digital Identities

This repository provides some additional material to the talk at Viscon held on the 16.10.22. It contains the slides, as well as some code samples to illustrate the algorithms mentioned. 

> It is by no means complete, and no guarantees regarding constant-time, or secure implementations is given. Rather it should help following the papers and understand what actually happens.

The code snippets are written in [Rust](https://rustup.rs), and should work (so far Rust has been installed) by just running `cargo run` in each of the folders.


## Note
For the Pedersen commitment and the Schnorr Protocol we use the [curve25519](https://en.wikipedia.org/wiki/Curve25519), where as for the CL signature we  work in the multiplicative group $Z_n$

## References

- [Camenisch-Lysyanskaya](https://cs.brown.edu/people/alysyans/papers/camlys02b.pdf)
- [Pedersen commitment](https://link.springer.com/content/pdf/10.1007/3-540-46766-1_9.pdf)
- [BBS+](https://eprint.iacr.org/2016/663.pdf)
- [Bulletproofs (Short ZKP)](https://eprint.iacr.org/2017/1066.pdf)

