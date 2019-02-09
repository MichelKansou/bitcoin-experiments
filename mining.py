from Crypto.Hash import SHA256
import time

text = "I am Satoshi Nakamoto"

max_nonce = 2 ** 32 # 4 billion

nonce = 0
hash_result = ''
difficulty_bits = 25 # for 25 nonce 39991487
target = 2 ** (256 - difficulty_bits)


# iterate nonce until hash is valid 
def proof_of_work(header):
    print("Target ", target)
    # checkpoint the current time
    start_time = time.time()

    for nonce in range(max_nonce):
        concat = str(header + str(nonce)).encode('utf-8')
        hash_result = SHA256.new(concat).hexdigest()
        #print(nonce)
        # check if this is a valid result, below the target
        if int(hash_result, 16) < target:
            print("Success with nonce %d" % nonce)
            print("Hash is %s" % hash_result)
            
            # checkpoint how long it took to find a result
            end_time = time.time()

            elapsed_time = end_time - start_time
            print("Elapsed Time: %.4f seconds" % elapsed_time)

            return (hash_result, nonce)


proof_of_work(text)