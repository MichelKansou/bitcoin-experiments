from bitcoin_protocol.helper import (
    bits_to_target,
    hash256,
    merkle_root,
    int_to_little_endian,
    little_endian_to_int,
)


GENESIS_BLOCK = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
)
TESTNET_GENESIS_BLOCK = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"
)
LOWEST_BITS = bytes.fromhex("ffff001d")


class Block:
    def __init__(
        self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    @classmethod
    def parse(cls, stream):
        """Takes a byte stream and parses the block header at the start
        return a Block object
        """

        # version is an integer in 4 bytes, little-endian
        version = little_endian_to_int(stream.read(4))
        # previous block is a 32 bytes little-endian reversed with [::-1]
        prev_block = stream.read(32)[::-1]
        # merkle root is a 32 bytes little-endian reversed with [::-1]
        merkle_root = stream.read(32)[::-1]
        # timestamp is an integer in 4 bytes, little-endian,
        timestamp = little_endian_to_int(stream.read(4))
        # bits is a 4 bytes
        bits = stream.read(4)
        # nonce is a 4 bytes
        nonce = stream.read(4)

        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        """Returns the 80 byte block header"""
        # version is an integer in 4 bytes, little-endian
        result = int_to_little_endian(self.version, 4)
        # previous block is an integer in 32 bytes, little-endian
        result += self.prev_block[::-1]
        # merkle root is an integer in 32 bytes, little-endian
        result += self.merkle_root[::-1]
        # timestamp is an integer in 4 bytes, little-endian,
        result += int_to_little_endian(self.timestamp, 4)
        # bits is an integer in 4 bytes, little-endian
        result += self.bits
        # nonce is an integer in 4 bytes, little-endian
        result += self.nonce

        return result

    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]

    def bip9(self):
        """Returns whether this block is signaling readiness for BIP9"""
        # BIP9 is signalled if the top 3 bits are 001
        # version is 32 bytes so right shift 29 (>> 29) and see if
        # that is 001
        if self.version >> 29 == 0b001:
            return True
        else:
            return False

    def bip91(self):
        """Returns whether this block is signaling readiness for BIP91"""
        # BIP91 is signalled if the 5th bit from the right is 1
        # shift 4 bits to the right and see if the last bit is 1
        if self.version >> 4 & 1 == 1:
            return True
        else:
            return False

    def bip141(self):
        """Returns whether this block is signaling readiness for BIP141"""
        # BIP91 is signalled if the 2nd bit from the right is 1
        # shift 1 bit to the right and see if the last bit is 1
        if self.version >> 1 & 1 == 1:
            return True
        else:
            return False

    def target(self):
        """Returns the proof-of-work target based on the bits"""
        return bits_to_target(self.bits)

    def difficulty(self):
        """Returns the block difficulty based on the bits"""
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest_diffculty = 0xFFFF * 256 ** (0x1D - 3)
        return lowest_diffculty / self.target()

    def check_pow(self):
        """Returns whether this block satisfies proof of work"""
        # get the hash256 of the serialization of this block
        block_hash = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(block_hash)
        # return whether this integer is less than the target
        return proof < self.target()

    def validate_merkle_root(self):
        """Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        """
        # reverse each item in self.tx_hashes
        reversed_tx_hashes = [h[::-1] for h in self.tx_hashes]
        # compute the Merkle Root and reverse
        checked_merkle_root = merkle_root(reversed_tx_hashes)[::-1]
        # return whether self.merkle_root is the same
        return self.merkle_root == checked_merkle_root
