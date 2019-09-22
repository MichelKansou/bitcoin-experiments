from helper import (
    hash256, 
    little_endian_to_int, 
    read_varint, 
    int_to_little_endian, 
    encode_varint
    )
from script import Script

from io import BytesIO
import json
import requests

class Tx:

    def __init__(self, version, tx_inputs, tx_outputs, locktime, testnet=False):
        self.version = version
        self.tx_inputs = tx_inputs
        self.tx_outputs = tx_outputs
        self.locktime = locktime
        self.testnet = testnet
    
    def id(self):
        # Human readable hexadecimal of the transaction hash
        return self.hash().hex()

    def hash(self):
        # Binary hash of the legacy serialization
        return hash256(self.serialize())[::-1]
    
    def __repr__(self):
        tx_inputs = ''
        for tx_input in self.tx_inputs:
            tx_inputs += tx_input.__repr__() + '\n'
        
        tx_outputs = ''
        for tx_output in self.tx_outputs:
            tx_outputs += tx_output.__repr__() + '\n'
        
        return 'tx: {}\n version: {}\n inputs: {}\n outputs: {}\n locktime: {}'.format(
            self.id(),
            self.version,
            tx_inputs,
            tx_outputs,
            self.locktime
            )

    def serialize(self):
        # Return the byte serialization of the transaction
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_inputs))
        for input in self.tx_inputs:
            result += TxIn.serialize(input)
        
        result += encode_varint(len(self.tx_outputs))
        
        for output in self.tx_outputs:
            result += TxOut.serialize(output)
        
        result += int_to_little_endian(self.locktime, 4)
        return result
    
    @classmethod
    def parse(classTx, stream, testnet=False):
        # read first 4 bytes that represent the transaction version
        serialized_version = stream.read(4)
        # convert bytes (little endian format) to integer
        version = little_endian_to_int(serialized_version)

        num_inputs = read_varint(stream)
        
        tx_inputs = []
        for _ in range(num_inputs):
            tx_inputs.append(TxIn.parse(stream))
        
        num_outputs = read_varint(stream)
        
        tx_outputs = []
        for _ in range(num_outputs):
            tx_outputs.append(TxOut.parse(stream))
        
        locktime = little_endian_to_int(stream.read(4))

        return classTx(version, tx_inputs, tx_outputs, locktime, testnet=testnet)

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        # use TxIn.value() to sum up the input amounts
        # use TxOut.amount to sum up the output amounts
        # fee is input sum - output sum
        sum_tx_input = 0
        sum_tx_output = 0
        for tx_input in self.tx_inputs:
            sum_tx_input += tx_input.value()
        
        for tx_output in self.tx_outputs:
            sum_tx_output += tx_output.amount
        
        print(sum_tx_input, sum_tx_output)
        return sum_tx_input - sum_tx_output

class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        
        self.sequence = sequence
    
    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index
        )

    def serialize(self):
        # Return the byte serialization of the transaction input
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result
    
    def fetch_tx(self, testnet=False):
        print(self.prev_tx.hex())
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        # Get the output value by looking up the tx hash
        # Returns the amount in satoshi
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outputs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        # Get the ScriptPubKey by looking up the tx hash
        # Return a Script object.
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outputs[self.prev_index].script_pubkey
    
    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)
        # prev_tx is 32 bytes, little endian
        # prev_index is an integer in 4 bytes, little endian
        # use Script.parse to get the ScriptSig
        # sequence is an integer in 4 bytes, little-endian
        # return an instance of the class (see __init__ for args)

class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey
    
    def __repr__(self):
        return '{}:{}'.format(
            self.amount,
            self.script_pubkey
        )
    
    def serialize(self):
        # Return the byte serialization of the transaction output
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result
    
    @classmethod
    def parse(cls, s):
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:  # <1>
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), 
                                  tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]