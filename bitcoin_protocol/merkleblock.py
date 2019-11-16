import math as m

from bitcoin_protocol.helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)


class MerkleTree:
    def __init__(self, total):
        self.total = total
        self.max_depth = m.ceil(m.log(self.total, 2))
        self.nodes = []

        for depths in range(self.max_depth + 1):
            depth_items = m.ceil(self.total / 2 ** (self.max_depth - depths))
            level_hashes = [None] * depth_items
            self.nodes.append(level_hashes)
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = "None"
                else:
                    short = "{}...".format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    items.append("*{}*".format(short[:2]))
                else:
                    items.append("{}".format(short))
            result.append(", ".join(items))
        return "\n".join(result)

    def up(self):
        self.current_depth -= 1
        self.current_index //= 2

    def left(self):
        self.current_depth += 1
        self.current_index *= 2

    def right(self):
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]

    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > (self.current_index * 2 + 1)

    def populate_tree(self, flag_bits, hashes):
        while self.root() is None:
            if self.is_leaf():
                flag_bits.pop(0)
                self.set_current_node(hashes.pop(0))
                self.up()
            else:
                left_hash = self.get_left_node()
                if left_hash is None:
                    if flag_bits.pop(0) == 0:
                        self.set_current_node(hashes.pop(0))
                        self.up()
                    else:
                        self.left()
                elif self.right_exists():
                    right_hash = self.get_right_node()
                    if right_hash is None:
                        self.right()
                    else:
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        self.up()
                else:
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    self.up()
        if len(hashes) != 0:
            raise RuntimeError("hashes not all consumed {}".format(len(hashes)))

        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError("flag bits not all consumed")


class MerkleBlock:
    def __init__(
        self,
        version,
        prev_block,
        merkle_root,
        timestamp,
        bits,
        nonce,
        total,
        hashes,
        flags,
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.total = total
        self.hashes = hashes
        self.flags = flags

    def __repr__(self):
        result = "{}\n".format(self.total)
        for h in self.hashes:
            result += "\t{}\n".format(h.hex())
        result += "{}".format(self.flags.hex())

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses a merkle block. Returns a Merkle Block object"""
        # version - 4 bytes, Little-Endian integer
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes (use [::-1])
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes (use [::-1])
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, Little-Endian integer
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # total transactions in block - 4 bytes, Little-Endian integer
        total = little_endian_to_int(s.read(4))
        # number of transaction hashes - varint
        num_hashes = read_varint(s)
        # each transaction is 32 bytes, Little-Endian
        hashes = []
        for _ in num_hashes:
            hashes.append(little_endian_to_int(s.read(32)[::-1]))
        # length of flags field - varint
        flags_length = read_varint(s)
        # read the flags field
        flags = s.read(flags_length)
        # initialize class
        return cls(
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            total,
            hashes,
            flags,
        )

    def is_valid(self):
        """Verifies whether the merkle tree information validates to the merkle root"""
        # convert the flags field to a bit field
        flag_bits = bytes_to_bit_field(self.flags)
        # reverse self.hashes for the merkle root calculation
        hashes = [h[::-1] for h in self.hashes]
        # initialize the merkle tree
        merkle_tree = MerkleTree(self.total)
        # populate the tree with flag bits and hashes
        merkle_tree.populate_tree(flag_bits, hashes)
        # check if the computed root reversed is the same as the merkle root
        # return whether self.merkle_root is the same
        return merkle_tree.root()[::-1] == self.merkle_root
