from io import BytesIO
from bitcoin_protocol.network import SimpleNode, GetHeadersMessage, HeadersMessage
from bitcoin_protocol.block import Block, GENESIS_BLOCK, LOWEST_BITS
from bitcoin_protocol.helper import calculate_new_bits

# Check Genesis Block
previous = Block.parse(BytesIO(GENESIS_BLOCK))
first_epoch_timestamp = previous.timestamp
expected_bits = LOWEST_BITS
count = 1

# Connect to a full node
host = "mainnet.programmingbitcoin.com"
port = 8333
node = SimpleNode(host, port=port, testnet=False)
node.handshake()

for _ in range(19):
    getheaders = GetHeadersMessage(start_block=previous.hash())
    node.send(getheaders)
    headers = node.wait_for(HeadersMessage)
    for block_header in headers.blocks:
        # Check that the proof of work is valid
        if not block_header.check_pow():
            raise RuntimeError("bad PoW at block {}".format(count))
        # Check that the current block is after the previous one
        if block_header.prev_block != previous.hash():
            raise RuntimeError("discontinuous block at {}".format(count))
        # Calculate current bits/target/difficulty
        if count % 2016 == 0:
            time_diff = previous.timestamp - first_epoch_timestamp
            # At the end of the epoch, calculate the next bits/target/difficulty
            expected_bits = calculate_new_bits(previous.bits, time_diff)
            print(
                "expected difficulty for block {} : {}".format(
                    count, expected_bits.hex()
                )
            )
            # Store the first block of the epoch to calculate bits at the end of the epoch
            first_epoch_timestamp = block_header.timestamp
        # Check that the bits/target/difficulty is what we expect based on the previous epoch calculation
        if block_header.bits != expected_bits:
            raise RuntimeError("bad bits at block {}".format(count))
        previous = block_header
        count += 1
