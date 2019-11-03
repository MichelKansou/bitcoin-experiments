import time
from random import randint
from io import BytesIO
import socket

from bitcoin_protocol.block import Block
from bitcoin_protocol.helper import (
    little_endian_to_int,
    int_to_little_endian,
    read_varint,
    encode_varint,
    hash256,
)


NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"
TESTNET_NETWORK_MAGIC = b"\x0b\x11\x09\x07"


class NetworkEnvelope:
    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return "{} : {}".format(self.command.decode("ascii"), self.payload.hex())

    @classmethod
    def parse(cls, s, testnet=False):
        """Takes a stream and creates a NetworkEnvelope"""
        # First 4 bytes are the network magic
        magic = s.read(4)
        if magic == b"":
            raise IOError("Connection reset!")
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise SyntaxError(
                "magic is not right {} vs {}".format(magic.hex(), expected_magic.hex())
            )

        # next 12 bytes are the command field
        # more details about each commands https://en.bitcoin.it/wiki/Protocol_documentation
        command = s.read(12)
        # remove trailing x00 bytes from command
        command = command.strip(b"\x00")

        # 4 bytes payload length in little endian
        payload_length = little_endian_to_int(s.read(4))

        # 4 bytes payload checksum first 4 bytes of hash256 of the payload
        payload_checksum = s.read(4)

        # payload
        payload = s.read(payload_length)

        # get first 4 bytes of the payload hash256
        calculated_checksum = hash256(payload)[:4]

        # check if the first 4 bytes hash256 of the payload match the checksum
        if calculated_checksum != payload_checksum:
            raise IOError("checksum does not match")
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        """Returns the byte serialization of the entire network message"""
        # add the network magic
        result = self.magic
        # command 12 bytes
        # fill with 0's
        result += self.command + b"\x00" * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += hash256(self.payload)[:4]
        # payload
        result += self.payload

        return result

    def stream(self):
        """Returns a stream for parsing the payload"""
        return BytesIO(self.payload)


class VersionMessage:
    command = b"version"

    def __init__(
        self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b"\x00\x00\x00\x00",
        receiver_port=8333,
        sender_services=0,
        sender_ip=b"\x00\x00\x00\x00",
        sender_port=8333,
        nonce=None,
        user_agent=b"/sackboy-node:3.1.3/",
        latest_block=0,
        relay=False,
    ):
        self.version = version
        self.services = services

        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp

        # init receiver info
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port

        # init sender info
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port

        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2 ** 64), 8)
        else:
            self.nonce = nonce

        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        timestamp = little_endian_to_int(s.read(8))
        receiver_services = little_endian_to_int(s.read(8))
        receiver_ip = s.read(16).strip(b"\x00").strip(b"\xff")
        receiver_port = int.from_bytes(s.read(2), "big")

        sender_services = little_endian_to_int(s.read(8))
        sender_ip = s.read(16).strip(b"\x00").strip(b"\xff")
        sender_port = int.from_bytes(s.read(2), "big")
        nonce = s.read(8)
        user_agent_len = read_varint(s)
        user_agent = s.read(user_agent_len)
        latest_block = little_endian_to_int(s.read(4))
        relay = s.read(1) == b"\x01"

        return cls(
            version,
            services,
            timestamp,
            receiver_services,
            receiver_ip,
            receiver_port,
            sender_services,
            sender_ip,
            sender_port,
            nonce,
            user_agent,
            latest_block,
            relay,
        )

    def serialize(self):
        """Serialize this message to send over the network"""
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += (b"\x00" * 10) + b"\xff\xff" + self.receiver_ip
        # receiver port is 2 bytes, little endian should be 0
        result += self.receiver_port.to_bytes(2, "big")
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += (b"\x00" * 10) + b"\xff\xff" + self.sender_ip
        # sender port is 2 bytes, little endian should be 0
        result += self.sender_port.to_bytes(2, "big")
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b"\x01"
        else:
            result += b"\x00"
        return result


class VerAckMessage:

    command = b"verack"

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls

    def serialize(self):
        return b""


class PingMessage:
    command = b"ping"

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b"pong"

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class GetHeadersMessage:
    command = b"getheaders"

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError("a start block is required")
        self.start_block = start_block
        if end_block is None:
            self.end_block = b"\x00" * 32
        else:
            self.end_block = end_block

    def serialize(self):
        """Serialize this message to send over the network"""
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # number of hashes varint
        result += encode_varint(self.num_hashes)
        # starting block little-endian
        result += self.start_block[::-1]
        # ending block little endian
        result += self.end_block[::-1]

        return result


class HeadersMessage:
    command = b"headers"

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        num_headers = read_varint(stream)
        blocks = []

        for _ in range(num_headers):
            blocks.append(Block.parse(stream))
            num_txs = read_varint(stream)
            if num_txs != 0:
                raise RuntimeError("number of txs not 0")
        return cls(blocks)


class SimpleNode:
    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile("rb", None)

    def send(self, message):
        # Send a message to the command node
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet
        )

        if self.logging:
            print("sending: {}".format(envelope))
        self.socket.sendall(envelope.serialize())

    def read(self):
        # Read message from the socket
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)

        if self.logging:
            print("receiving: {}".format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        # Wait for one of the message in the list
        command = None
        command_to_class = {m.command: m for m in message_classes}

        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(envelope.stream())

    def handshake(self):
        """Do a handshake with the other node.
        Handshake is sending a version message and getting a verack back."""
        # create a version message
        version = VersionMessage()
        # send the command
        self.send(version)
        # wait for a verack message
        self.wait_for(VerAckMessage)
