# Frequently answered questions

## What is the scope of this specification?

The scope of this specification covers non-interactive, 3-message arguments for proving knowledge of a private $x \in \mathbb{F}^n$ such that:

$$Ax = B$$

where $A \in \mathbb{G}^{m \times n}$ and $B \in \mathbb{G}^m$ are public. These are sometimes informally called _Schnorr proofs_ [Schnorr91], _Maurer proofs_ [[Maurer09]](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf).

This specification will focus on ciphersuites in elliptic curve groups.
This specification will **NOT** include:
- Proofs over RSA groups, multiplicative group of integers modulo a prime number, or lattices;
- AND and OR composition of sigma protocols;
- Compressed Sigma protocols;
- Recursive arguments via algebraic hash functions;
- Sigma protocols from MPC-in-the-Head techniques;

However, the API and the primitives WILL BE described in such a way that all these things MAY be built on top in future drafts, given the prominence of all these techniques.

## CFRG Questions

### Why isn’t it solved already?

> Clearly state existing limitations in current cryptographic tools, techniques, or approaches that justify why new research or analysis is required. Highlight specific gaps or weaknesses that your proposal intends to address, demonstrating both the necessity and innovation of the proposed research.

Sigma protocols have been formalized over 30 years ago. However, due to [a patent](https://patents.google.com/patent/US4995082A/en) from Claus Schnorr they haven't been widely adopted yet. This is also part of the reason why cryptographers designed DSA in the way it is designed.

Previous RFCs that describe how to perform these type of proofs are:
- [RFC8235](https://datatracker.ietf.org/doc/html/rfc8235), which is a Schnorr proof for proving knowledge of $x$ such that $xG = X$. In other words, it is a proof for 
```math
   \begin{bmatrix}G \end{bmatrix} x = \begin{bmatrix} X \end{bmatrix}\enspace.
```
- [RFC9497](https://datatracker.ietf.org/doc/html/rfc9497#section-2.2), which is a Schnorr proof for proving knowledge of $x$ such that $xG = X$ and $x H = Y$. In other words, it is a proof for

```math
   \begin{bmatrix}G \\ H \end{bmatrix} x = \begin{bmatrix} X \\ Y\end{bmatrix}\enspace.
```

They are therefore a specialization of the proofs we are trying to standardize.

### Is this actually an engineering problem instead of a research problem?

> CFRG primarily addresses issues requiring new cryptographic insights, theoretical developments, or rigorous security analyses. If your problem predominantly concerns implementation details, performance optimization, or configuration choices using well-understood cryptography, it might be more appropriately handled within an IETF working group. Distinguishing between engineering and research problems helps ensure proposals align correctly with CFRG’s scope.

Several current CFRG drafts rely on Sigma Protocols, necessitating a comprehensive study to harmonize these efforts. This specification aims to establish an interoperable, standardized framework for proving statements. Key research objectives include:

- Eliminating redundancy across specifications without over-generalizing, addressing both deployed code efficiency and resource allocation in the standardization process
- Enhancing security in existing drafts by preventing proof reuse attacks and evaluating protocol implementation within the broader ecosystem

Specific Drafts Requiring Harmonization:

1. **[draft-yun-cfrg-arc](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc/)**: Implements a Maurer proof compiler for rate-limiting Privacy Pass credentials.

2. **BBS Standards Framework**: [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) provides a "compiled" Schnorr proof subsequently re-specified in:
   - [draft-kalos-bbs-blind-signatures](https://datatracker.ietf.org/doc/draft-kalos-bbs-blind-signatures/)
   - [draft-irtf-cfrg-bbs-per-verifier-linkability](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/)
   - [draft-ladd-privacypass-bbs](https://datatracker.ietf.org/doc/draft-ladd-privacypass-bbs/)

   Consolidating these drafts would significantly reduce specification volume for Crypto Review Panel evaluation, decrease deployed code size, and facilitate smoother integration of future extensions within the BBS ecosystem.

3. **[draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)**: Currently employs an ad-hoc, unproven Fiat-Shamir transformation requiring formal verification.

This standardization effort represents both an engineering challenge and a cryptographic research problem requiring rigorous mathematical analysis and security evaluation.

### Is the research mature enough for CFRG engagement?

> CFRG typically expects some level of research maturity, evidenced by published results, analyses, or strong community discussion. If the problem or proposed solution is too early—lacking peer-reviewed analyses, preliminary security proofs, or significant academic attention—it may not yet be suitable for CFRG adoption. In these cases, authors might consider first pursuing academic validation or informal community vetting before bringing it to CFRG.

Research in this topic has not been significantly revisited in the last 30 years, and we do not expect it to change. We have a [dedicated page](https://sigma.zkproof.org/history) for the history of this proof system.

### Scope and impact: Clarify how broad, significant, or urgent the identified cryptographic problem is.

> Is the proposal addressing a minor adjustment or filling a fundamental gap? Determine if solving it involves addressing several sub-problems or just a narrow issue​. Clearly defining the scope and potential impact helps CFRG evaluate whether the effort required justifies the proposed research group effort and helps the group avoid revisiting fundamental questions later.

We view this as laying the ground for standardizing zero-knoweldge proofs. There are currently 8 drafts and RFCs under the IETF hat requiring zero-knowledge proofs.
Outside IETF, we have:
- [NIST's call on multi-party threshold cryptography](https://csrc.nist.gov/projects/threshold-cryptography) targeting also proofs of knowledge of signing keys;
- [W3C's Decentralized Identifiers](https://www.w3.org/TR/did-1.0/), requiring anonymity across presentation of the credentials;
- [The European Union Digital Identity legislation](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/discussion-topics/g-zero-knowledge-proof.md), which mandates a specification for zero-knowledge proofs **by September 2025**.

Besides laws and standards, within the corporate environment the following large-scale industries are currently exploring proofs covered by this specification:
- [Google](https://github.com/SamuelSchlesinger/authenticated-pseudonyms/blob/dev/combined/design/Private_BBS_Security.pdf), for authenticated pseudonym.
- [Apple](https://github.com/chris-wood/draft-arc/blob/main/draft-yun-cfrg-arc.md), for rate-limiting credentials.

The following "public good cryptographic" projects are relying on the proofs covered by this draft:
- [Tor](https://gitlab.torproject.org/tpo/anti-censorship/lox/-/tree/main/crates/lox-library?ref_type=heads), for bridge distribution;
- [Signal](https://github.com/signalapp/libsignal/blob/main/rust/poksho/), for group chat management;


### Expertise and feasibility: Assess whether CFRG has the right expertise available among its community members to effectively address this problem.

> Clearly state any specific requirements related to performance, security levels, hardware constraints, or other practical considerations. Ensuring that the community has the requisite expertise and resources improves the likelihood that your proposal will be effectively addressed and adopted by CFRG.


Sigma protocols are taught today in cryptography 101 classes. The Crypto Panel of CFRG is well-qualified to review this draft.
