# [Specification for Sigma Protocols](https://sigma.zkproof.org)

## Introduction

This is the working area for the specification on Sigma Protocols, a standardization effort focusing on zero-knowledge proof systems including:
- *Schnorr proofs* [[Schnorr91]](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
- *Maurer proofs* [[Maurer09]](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf) 
- Related protocols introduced by Camenisch and Stadler [[CamenischS97]](https://www.research-collection.ethz.ch/bitstream/handle/20.500.11850/69316/eth-3353-01.pdf)

For more information about the scope of this project and frequently-asked questions, please check out the [FAQ](https://github.com/mmaker/draft-zkproof-sigma-protocols/blob/main/FAQ.md).

**Reference implementations** and **updates** are posted on our website: [sigma.zkproof.org](https://sigma.zkproof.org).

## Documentation

### Sigma Protocols Specification

* [Editor's Copy](https://mmaker.github.io/draft-zkproof-sigma-protocols/draft-orru-zkproof-sigma-protocols.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-orru-zkproof-sigma-protocols)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-orru-zkproof-sigma-protocols)
* [Compare Versions](https://mmaker.github.io/draft-zkproof-sigma-protocols/compare.html?from=draft-orru-zkproof-sigma-protocols&to=latest)

### Fiat-Shamir Heuristic

* [Editor's Copy](https://mmaker.github.io/draft-zkproof-sigma-protocols/draft-orru-zkproof-fiat-shamir.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-orru-zkproof-fiat-shamir)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-orru-zkproof-fiat-shamir)
* [Compare Versions](https://mmaker.github.io/draft-zkproof-sigma-protocols/compare.html?from=draft-orru-zkproof-fiat-shamir&to=latest)

## Contributing

We welcome contributions to this standardization effort. Please see the
[guidelines for contributions](https://github.com/mmaker/draft-zkproof-sigma-protocols/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests on GitHub. The GitHub interface supports creating pull requests using the Edit (✏) button.

## Building the Specification and Test Vectors

### Requirements

To build and test this project, you'll need:
- Required tools for formatting drafts (see [setup instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md))
- [SageMath](https://www.sagemath.org/) (for running the proof of concept implementation)

### Building the Documentation

Formatted text and HTML versions of the draft can be built using `make`:

```sh
$ make
```

### Running the Proof of Concept

The proof of concept implementation is located in the [`poc/`](https://github.com/mmaker/draft-zkproof-sigma-protocols/tree/main/poc) directory. This implementation provides concrete examples of the protocols described in the specification and generates test vectors for validation.

To run the unit tests for the proof of concept:

```sh
$ cd poc/
$ make test
```

## References

- [Schnorr91] Schnorr, C.P. (1991) Efficient Signature Generation by Smart Cards. Journal of Cryptology, 4, 161-174.
- [Maurer09] Maurer, U. (2009). Unifying Zero-Knowledge Proofs of Knowledge. In B. Preneel (Ed.), Progress in Cryptology – AFRICACRYPT 2009 (pp. 272-286). Springer.
- [CamenischS97] Camenisch, J., & Stadler, M. (1997). Proof Systems for General Statements about Discrete Logarithms. Technical Report 260, ETH Zürich.
