from sagelib.fiat_shamir import NIZK
from sagelib.duplex_sponge import SHAKE128, KeccakDuplexSponge
from sagelib.sigma_protocols import SchnorrProof
from sagelib.codec import P256Codec, Bls12381Codec

class NISchnorrProofShake128P256(NIZK):
    Protocol = SchnorrProof
    Codec = P256Codec
    Hash = SHAKE128


class NISchnorrProofShake128Bls12381(NIZK):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = SHAKE128


class NISchnorrProofKeccakDuplexSpongeBls12381(NIZK):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = KeccakDuplexSponge


CIPHERSUITE = {
    "sigma/Shake128+P256": NISchnorrProofShake128P256,
    "sigma/Shake128+BLS12381": NISchnorrProofShake128Bls12381,
    "sigma/OWKeccak1600+Bls12381": NISchnorrProofKeccakDuplexSpongeBls12381,
}