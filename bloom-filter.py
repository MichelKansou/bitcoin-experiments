from Crypto.Hash import SHA256
from bitarray import bitarray
import math

# source https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch08.asciidoc#bloom-filters
# source https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/


class bloom_filter:

    def __init__(self, fp_prob, items_count):
        # False posible probability in decimal
        self.fp_prob = fp_prob

        # Size of bit array to use
        self.size = self.get_size(items_count, fp_prob)  # length of bit array

        self.items_count = items_count  # number of items to hash
        self.bits = bitarray(self.size)  # the actual bit store

        # initialize all bits as 0
        self.bits.setall(0)

    # hi(s)=SHA256(i ∣∣ s) mod m
    # Where:
    # i - the number of the hash function.
    # s - the string to be hashed.
    # m - the length of the bit vector.
    # ∣∣ - string concatenation.

    def hash(self, items_count, bit_vector_length, string):
        hex_bytes = bytes(items_count) + string.encode("utf-8")
        return int(SHA256.new(hex_bytes).hexdigest(), 16) % bit_vector_length

    def add(self, string):
        for i in range(self.items_count):
            self.bits[self.hash(i, self.size, string)] = 1

    def contains(self, string):
        for i in range(self.items_count):
            if self.bits[self.hash(i, self.size, string)] == 0:
                return False
        return True

    def get_size(self, n, p):
        '''
        Return the size of bit array(m) to used using
        following formula
        m = -(n * lg(p)) / (lg(2)^2)
        n : int
            number of items expected to be stored in filter
        p : float
            False Positive probability in decimal
        '''
        m = -(n * math.log(p))/(math.log(2)**2)
        return int(m)


items = 10  # no of items to add
fp_prob = 0.05  # false positive probability

bloomTest = bloom_filter(fp_prob, items)

bloomTest.add('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
bloomTest.add('3CxQAYsgdDyS3BXYVy6aMUqe1AmVVSawUF')
bloomTest.add('39HbntmSpWcfMoYMSTfyp55tkk85qMMX55')
bloomTest.add('1btcme9vKh2b1i7zRhnZRxThki1dqdsNK')
bloomTest.add('3LFAbYWYcpMkkrucNqpbpuUM7HEEo5X5Fz')
bloomTest.add('156r76q1cTARi4xTZvywHkdLPWKsZhU7kj')
bloomTest.add('12bRG8o7X8JfFaoUYfWokepmLansFzp4K9')
bloomTest.add('3NzEgtMaUeg71YRjhqyKE5tyGxFWgpjEZk')
bloomTest.add('18888889eCDXmBodBNQWRNpMM26Fssirz4')
bloomTest.add('1PHtWpw9n5FxQtg2AcMuXpBDS6p1NgHuzg')


print(bloomTest.bits)

print(bloomTest.contains('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))  # True
print(bloomTest.contains('1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf00'))  # False
print(bloomTest.contains('1btcme9vKh2b1i7zRhnZRxThki1dqdsNK'))  # True
