from Crypto.Hash import SHA256


def mergeHash (hash_1, hash_2):
    # Create a bytes object from a string of hexadecimal numbers
    hex_bytes = (bytes.fromhex(hash_2+hash_1))[::-1] # [::-1] for a reverse

    # Create double sha 256 of concat hashes
    double_hash = SHA256.new(SHA256.new(hex_bytes).digest()).digest()

    # Return a reverse hexadecimal numbers of bytes
    return  double_hash[::-1].hex()
    
class Transaction:
  def __init__(self, sender, recepient, tx_hash, amounts):
    self.sender = sender
    self.recepient = recepient
    self.tx_hash = tx_hash
    self.amounts = amounts

transactions = []

# Block 
#https://www.blockchain.com/fr/btc/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
transactions.append(Transaction("coinbase", "1HWqMzw1jfpXb3xyuUZ4uWXY4tqL2cW47J", "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87", "50"))
transactions.append(Transaction("1BNwxHGaFbeUBitpjy2AsKpJ29Ybxntqvb", "1JqDybm2nWTENrHvMyafbSXXtTk5Uv5QAn,1EYTGtG4LnFfiMvjJdsU7GMGCQvsRSjYhx", "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4", "50"))
transactions.append(Transaction("15vScfMHNrXN4QvWe54q5hwfVoYwG79CS1", "1H8ANdafjpqYntniT3Ddxh4xPBMCSz33pj,1Am9UTGfdnxabvcywYG2hvzr6qK8T3oUZT", "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4", "3"))
transactions.append(Transaction("1JxDJCyWNakZ5kECKdCU9Zka6mh34mZ7B2", "16FuTPaeRSPVxxCnwQmdyx2PQWxX6HWzhQ", "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d", "0.01"))

transactions_hash = []

for tx in transactions:
    transactions_hash.append(tx.tx_hash)

merkle_root = ''

while len(transactions_hash) > 1:
    tmp_tx = []

    for tx_v, tx_w in zip(transactions_hash[0::2], transactions_hash[1::2]):
        hash_pair = mergeHash(tx_v, tx_w)
        tmp_tx.append(hash_pair)

    if len(transactions_hash) % 2 != 0:
        hash_pair = mergeHash(transactions_hash[-1], transactions_hash[-1])
        tmp_tx.append(hash_pair)

    transactions_hash = tmp_tx
merkle_root = transactions_hash[0]

print("Merkle Root : ", merkle_root)

if merkle_root == 'f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766' :
    print("Merkle Root is valid")
else :
    print("Merkle Root is invalid")
