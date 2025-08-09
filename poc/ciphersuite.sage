from sagelib.fiat_shamir import NISigmaProtocol
from sagelib.duplex_sponge import KeccakDuplexSponge
from sagelib.sigma_protocols import SchnorrProof
from sagelib.codec import P256Codec, Bls12381Codec

class NISchnorrProofKeccakDuplexSpongeP256(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = P256Codec
    Hash = KeccakDuplexSponge


class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = KeccakDuplexSponge


CIPHERSUITE = {
    "sigma/OWKeccak1600+P256": NISchnorrProofKeccakDuplexSpongeP256,
    "sigma/OWKeccak1600+BLS12381": NISchnorrProofKeccakDuplexSpongeBls12381,
}