import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(str):
    count = 0
    for char in str:
        if char == 0:
            count += 1
        else:
            break
    num = int.from_bytes(str, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def hash256(s):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58_checksum(b):
    # 1 - do hash256 of address and get first 4 bytes
    # 2 - Take the combination of address and the 4 bytes encoded it in Base58
    return encode_base58(b + hash256(b)[:4])

def hash160(str):
    # sha256 followed by ripemd160
    return hashlib.new('ripemd160', hashlib.sha256(str).digest()).digest()

# little_endian_to_int takes byte sequence as a little-endian number and returns an integer
def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

# endian_to_little_endian takes an integer and returns the little-endian byte sequence of length
def int_to_little_endian(num, length):
    return num.to_bytes(length, 'little')