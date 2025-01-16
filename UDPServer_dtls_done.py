
import base64
import json
import os
import jsonpickle
import hmac
from blockchain2 import *
import time
import struct
import traceback
import hashlib
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from scapy.all import *
from scapy.layers.inet import UDP, IP
import ast
from harakav2 import pad_message, haraka512256
from falcon import falcon
from NTRU import ntru
import numpy as np


# dtls_constants.py

# Content Types
class ContentType:
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


# Handshake Message Types
class HandshakeType:
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

    @staticmethod
    def get_name(msg_type):
        types = {
            0: "HELLO_REQUEST",
            1: "CLIENT_HELLO",
            2: "SERVER_HELLO",
            3: "HELLO_VERIFY_REQUEST",
            11: "CERTIFICATE",
            12: "SERVER_KEY_EXCHANGE",
            13: "CERTIFICATE_REQUEST",
            14: "SERVER_HELLO_DONE",
            15: "CERTIFICATE_VERIFY",
            16: "CLIENT_KEY_EXCHANGE",
            20: "FINISHED"
        }
        return types.get(msg_type, f"UNKNOWN({msg_type})")


# Protocol Versions
class ProtocolVersion:
    DTLS_1_0 = b'\xfe\xff'
    DTLS_1_2 = b'\xfe\xfd'


# Alert Types
class AlertType:
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    HANDSHAKE_FAILURE = 40
    CERTIFICATE_EXPIRED = 45
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    INSUFFICIENT_SECURITY = 71


# Cipher Suites
class CipherSuite:
    TLS_RSA_WITH_AES_128_CBC_SHA = b'\x00\x2F'
    TLS_RSA_WITH_AES_256_CBC_SHA = b'\x00\x35'


# Record Layer Constants
class RecordLayer:
    HEADER_LENGTH = 13  # DTLS record header length
    MAX_FRAGMENT_LENGTH = 2 ** 14  # Maximum fragment length
    SEQUENCE_NUMBER_LENGTH = 8  # 8 bytes for epoch (2) + sequence number (6)


# Handshake Constants
class HandshakeLayer:
    HEADER_LENGTH = 12  # DTLS handshake header length
    MAX_FRAGMENT_LENGTH = 2 ** 14  # Maximum handshake fragment length
    CLIENT_RANDOM_LENGTH = 32
    SERVER_RANDOM_LENGTH = 32
    SESSION_ID_MAX_LENGTH = 32
    VERIFY_DATA_LENGTH = 12  # Length of verify data in Finished message


# Cookie Constants
class CookieSettings:
    MIN_LENGTH = 1
    MAX_LENGTH = 32
    DEFAULT_LIFETIME = 60  # seconds


# Timeouts and Retransmission
class TimeoutSettings:
    INITIAL_TIMEOUT = 1.0  # seconds
    MAX_TIMEOUT = 60.0  # seconds
    MAX_TRANSMISSIONS = 5

class BlockchainCertificateHandler:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache

    def verify_certificate(self, cert_data, block_hash):
        """Verify certificate using blockchain"""
        # Check cache first
        cache_key = f"{cert_data['pub_key_s_h']}:{block_hash}"
        if cache_key in self.cache:
            cache_time, result = self.cache[cache_key]
            if time.time() - cache_time < self.cache_ttl:
                return result

        # Verify on blockchain
        try:
            # Get certificate block from blockchain
            cert_block = self._get_certificate_block(block_hash)
            if not cert_block:
                return False

            # Verify certificate data matches blockchain record
            if not self._verify_cert_data(cert_data, cert_block):
                return False

            # Verify block proof of work
            if not self.blockchain.proof_of_work(cert_block):
                return False

            # Cache result
            self.cache[cache_key] = (time.time(), True)
            return True

        except Exception as e:
            print(f"Certificate verification error: {e}")
            return False

    def _get_certificate_block(self, block_hash):
        """Get certificate block from blockchain"""
        for block in self.blockchain.chain:
            if block.hashid == block_hash:
                return block
        return None

    def _verify_cert_data(self, cert_data, cert_block):
        """Verify certificate data matches blockchain record"""
        block_cert = cert_block.transactions
        required_fields = ['country', 'state', 'org', 'cname', 'pub_key_s_h']

        for field in required_fields:
            if cert_data.get(field) != block_cert.get(field):
                return False

        return True



class DTLSError(Exception):
    """Base class for DTLS protocol errors"""
    pass


class DTLSTimeout(DTLSError):
    """Raised when a DTLS operation times out"""
    pass


class DTLSVerificationError(DTLSError):
    """Raised when message verification fails"""
    pass


class DTLSState:
    """DTLS protocol states"""
    INITIAL = 0
    COOKIE_WAIT = 1
    COOKIE_SENT = 2
    SERVER_HELLO_WAIT = 3
    SERVER_HELLO_DONE_WAIT = 4
    CLIENT_FLIGHT_WAIT = 5
    FINISHED = 6


class DTLSSession:
    """DTLS session management"""

    def __init__(self):
        self.client_random = None
        self.server_random = None
        self.master_secret = None
        self.state = DTLSState.INITIAL
        self.cipher_suite = None
        self.session_id = os.urandom(32)
        self.peer_certificate = None
        self.sequence_numbers = {
            'read': 0,
            'write': 0
        }
        self.epoch = 0

    def derive_keys(self):
        """Derive encryption keys"""
        if not (self.client_random and self.server_random and self.master_secret):
            raise DTLSError("Missing key material")
        # Key derivation implementation would go here
        pass

    def increment_seq(self, direction):
        """Increment sequence number"""
        self.sequence_numbers[direction] += 1
        if self.sequence_numbers[direction] >= 2 ** 48:
            raise DTLSError("Sequence number overflow")

    def new_epoch(self):
        """Start new epoch"""
        self.epoch += 1
        if self.epoch >= 2 ** 16:
            raise DTLSError("Epoch overflow")
        self.sequence_numbers = {
            'read': 0,
            'write': 0
        }


def verify_finished_message(self, finished_data, expected_verify_data):
    """Verify Finished message contents"""
    try:
        if len(finished_data) < 12:
            raise DTLSVerificationError("Finished message too short")

        verify_data = finished_data[-12:]
        if not hmac.compare_digest(verify_data, expected_verify_data):
            raise DTLSVerificationError("Finished verification failed")

        return True

    except Exception as e:
        print(f"Error verifying Finished message: {e}")
        return False


def create_verify_data(self, handshake_messages):
    """Create verify_data for Finished message"""
    try:
        # In real implementation, this would use
        # PRF(master_secret, finished_label, Hash(handshake_messages))
        return os.urandom(12)  # Placeholder
    except Exception as e:
        print(f"Error creating verify data: {e}")
        return None

class DTLSRecordLayer:

    def __init__(self):
        self.epoch = 0
        self.sequence_number = 0

    def create_record_header(self, content_type, length):
        """Create DTLS record layer header"""
        return (
            bytes([content_type]) +  # Content type (22 for handshake)
            b'\xfe\xfd' +  # DTLS 1.2 version
            struct.pack("!H", self.epoch) +  # Epoch
            struct.pack("!Q", self.sequence_number)[:6] +  # Sequence number (48-bit)
            struct.pack("!H", length)  # Length
        )

    def increment_seq(self):
        self.sequence_number += 1
        if self.sequence_number >= 2 ** 48:
            raise ValueError("Sequence number overflow")

    def new_epoch(self):
        self.epoch += 1
        if self.epoch >= 2 ** 16:
            raise ValueError("Epoch overflow - need new connection")
        self.sequence_number = 0


class DTLSHandshake:
    def __init__(self, record_layer, cert_handler):
        self.message_seq = 0
        self.client_random = None
        self.server_random = None
        self.session_id = os.urandom(32)
        self.record_layer = record_layer
        self.cert_handler = cert_handler
        self.handshake_messages = []  # For verification
        self.cipher_suites = [
            b'\x00\x2F',  # TLS_RSA_WITH_AES_128_CBC_SHA
            b'\x00\x35'  # TLS_RSA_WITH_AES_256_CBC_SHA
        ]

    def create_handshake_header(self, msg_type, length, seq=None, frag_offset=0):
        """Create DTLS handshake header with sequence tracking"""
        if seq is None:
            seq = self.message_seq
            self.message_seq += 1

        header = (
                bytes([msg_type]) +  # Handshake type
                struct.pack("!I", length)[1:] +  # Length (24-bit)
                struct.pack("!H", seq) +  # Message sequence
                struct.pack("!I", frag_offset)[1:] +  # Fragment offset (24-bit)
                struct.pack("!I", length)[1:]  # Fragment length (24-bit)
        )

        return header

    def process_handshake_message(self, data, expected_type):
        """Process incoming handshake message"""
        try:
            if len(data) < 12:  # Minimum handshake header size
                raise DTLSError("Handshake message too short")

            msg_type = data[0]
            msg_len = struct.unpack("!I", b'\x00' + data[1:4])[0]
            msg_seq = struct.unpack("!H", data[4:6])[0]
            frag_offset = struct.unpack("!I", b'\x00' + data[6:9])[0]
            frag_len = struct.unpack("!I", b'\x00' + data[9:12])[0]
            print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")

            if msg_type != expected_type:
                raise DTLSError(f"Unexpected message type: {msg_type}, expected: {expected_type}")

            # Store message for finished verification
            self.handshake_messages.append(data)

            return data[12:12 + msg_len]  # Return message body

        except Exception as e:
            raise DTLSError(f"Error processing handshake message: {e}")

    def create_change_cipher_spec(self):
        """Create ChangeCipherSpec message"""
        return self.record_layer.create_record_header(
            content_type=20,  # ChangeCipherSpec
            length=1
        ) + b'\x01'

    def create_finished(self, master_secret):
        """Create Finished message with proper verification"""
        verify_data = self.calculate_verify_data(master_secret)

        finished_msg = self.create_handshake_header(
            msg_type=20,  # Finished
            length=len(verify_data)
        ) + verify_data

        record = self.record_layer.create_record_header(
            content_type=22,  # Handshake
            length=len(finished_msg)
        ) + finished_msg

        return record

    def calculate_verify_data(self, master_secret):
        """Calculate verify_data for Finished message"""
        if not self.handshake_messages:
            raise DTLSError("No handshake messages to verify")

        # Concatenate all handshake messages
        messages = b''.join(self.handshake_messages)

        # Calculate verify data using PRF
        verify_data = self.prf(
            master_secret,
            b'client finished' if self.is_client else b'server finished',
            messages,
            12  # verify_data length
        )

        return verify_data

    def prf(self, secret, label, seed, length):
        """DTLS PRF implementation"""
        # Implementation of TLS 1.2 PRF using SHA-256
        hmac_sha256 = lambda key, msg: hmac.new(key, msg, hashlib.sha256).digest()

        # P_hash implementation
        def p_hash(secret, seed, length):
            result = b''
            a = seed
            while len(result) < length:
                a = hmac_sha256(secret, a)
                result += hmac_sha256(secret, a + seed)
            return result[:length]

        return p_hash(secret, label + seed, length)
class DTLSCookieManager:
    def __init__(self):
        self.secret = os.urandom(32)
        self.cookie_lifetime = 60  # 60 seconds lifetime

    def extract_cookie_data(self, client_ip, client_port, client_hello):
        """Extract stable data for cookie generation"""
        try:
            # Skip record header (13 bytes) and handshake header (12 bytes)
            hello_data = client_hello[25:]

            # Get client random (32 bytes, starting after version)
            client_random = hello_data[2:34]

            # Cookie data is IP + Port + ClientRandom
            cookie_data = client_ip.encode() + str(client_port).encode() + client_random
            return cookie_data

        except Exception as e:
            print(f"Error extracting cookie data: {e}")
            return None

    def generate_cookie(self, client_ip, client_port, client_hello):
        """Generate cookie for HelloVerifyRequest"""
        cookie_data = self.extract_cookie_data(client_ip, client_port, client_hello)
        if not cookie_data:
            return None

        # Add current timestamp
        timestamp = struct.pack("!Q", int(time.time()))

        # Generate HMAC using secret key
        cookie = hmac.new(
            self.secret,
            cookie_data + timestamp,
            hashlib.sha256
        ).digest()

        print(f"Cookie generation:")
        print(f"Client IP: {client_ip}")
        print(f"Client Port: {client_port}")
        print(f"Cookie data: {cookie_data.hex()}")
        print(f"Generated cookie: {cookie.hex()}")

        return cookie

    def verify_cookie(self, received_cookie, client_ip, client_port, client_hello):
        """Verify received cookie"""
        try:
            cookie_data = self.extract_cookie_data(client_ip, client_port, client_hello)
            if not cookie_data:
                print("Failed to extract cookie data during verification")
                return False

            # Try timestamps within a window
            now = int(time.time())

            print("\nCookie Verification Debug:")
            print(f"Received Cookie: {received_cookie.hex()}")
            print(f"Original Cookie Data: {cookie_data.hex()}")

            # Try with current timestamp first
            timestamp = struct.pack("!Q", now)
            expected_cookie = hmac.new(
                self.secret,
                cookie_data + timestamp,
                hashlib.sha256
            ).digest()

            if hmac.compare_digest(received_cookie, expected_cookie):
                print("Cookie verification successful")
                return True

            # Try timestamps within window
            for t in range(now - self.cookie_lifetime, now):
                timestamp = struct.pack("!Q", t)
                expected_cookie = hmac.new(
                    self.secret,
                    cookie_data + timestamp,
                    hashlib.sha256
                ).digest()

                print(f"Testing timestamp {t}:")
                print(f"Expected cookie: {expected_cookie.hex()}")
                print(f"Received cookie: {received_cookie.hex()}")

                if hmac.compare_digest(received_cookie, expected_cookie):
                    print("Cookie verification successful")
                    return True

            print("Cookie verification failed - no timestamp matched")
            return False

        except Exception as e:
            print(f"Error during cookie verification: {e}")
            traceback.print_exc()
            return False

class DTLSServer:

    def __init__(self, server_ip, server_port):
        # Load server certificate and keys
        self.data_server = np.load('server_cert.npy', allow_pickle='TRUE').item()
        self.pub_key = self.data_server['pub_key_s_h']
        self.priv_key_sf = self.data_server['sk_f']
        self.priv_key_sg = self.data_server['sk_g']

        # Server configuration
        self.server_ip = server_ip
        self.server_port = server_port

        # Initialize blockchain
        self.blockchain = Blockchain(difficulty=20)

        # Initialize certificate handler
        self.cert_handler = BlockchainCertificateHandler(self.blockchain)

        # Initialize DTLS components
        self.record_layer = DTLSRecordLayer()
        self.handshake = DTLSHandshake(self.record_layer, self.cert_handler)

        # Generate initial server random and session ID
        self.handshake.server_random = os.urandom(HandshakeLayer.SERVER_RANDOM_LENGTH)
        self.handshake.session_id = os.urandom(32)

        self.cookie_manager = DTLSCookieManager()

        # Session state
        self.shared_secret = None
        self.client_random = None
        self.client_cipher_suite = None
        self.state = DTLSState.INITIAL

        print(f"DTLS Server initialized on {server_ip}:{server_port}")

    def parse_client_hello(self, data):
        """Parse ClientHello message"""
        try:
            print(f"\nParsing raw message ({len(data)} bytes):")
            print(f"Full message: {data.hex()}")

            # Validate record layer
            if len(data) < 13:
                raise ValueError(f"Packet too short for DTLS record header: {len(data)} bytes")

            record_type = data[0]
            if record_type != 0x16:  # Handshake type
                raise ValueError(f"Expected record type 0x16, got: 0x{record_type:02x}")

            record_version = data[1:3]
            epoch = data[3:5]
            seq_num = data[5:11]
            record_length = struct.unpack("!H", data[11:13])[0]

            print("\nRecord Layer:")
            print(f"Type: 0x{record_type:02x}")
            print(f"Version: {record_version.hex()}")
            print(f"Epoch: {epoch.hex()}")
            print(f"Sequence: {seq_num.hex()}")
            print(f"Length: {record_length}")

            # Parse handshake header
            handshake_data = data[13:]
            if len(handshake_data) < 12:
                raise ValueError("Data too short for handshake header")

            msg_type = handshake_data[0]
            msg_len = struct.unpack("!I", b'\x00' + handshake_data[1:4])[0]
            msg_seq = struct.unpack("!H", handshake_data[4:6])[0]
            frag_offset = struct.unpack("!I", b'\x00' + handshake_data[6:9])[0]
            frag_len = struct.unpack("!I", b'\x00' + handshake_data[9:12])[0]
            print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")

            print("\nHandshake Header:")
            print(f"Type: 0x{msg_type:02x}")
            print(f"Length: {msg_len}")
            print(f"Sequence: {msg_seq}")
            print(f"Fragment offset: {frag_offset}")
            print(f"Fragment length: {frag_len}")

            # Parse ClientHello body
            hello_data = handshake_data[12:]
            if len(hello_data) < 34:
                raise ValueError("Data too short for ClientHello minimum")

            client_version = hello_data[0:2]
            client_random = hello_data[2:34]
            session_id_len = hello_data[34]
            offset = 35 + session_id_len

            if len(hello_data) < offset + 1:
                raise ValueError("Data too short for cookie length")

            cookie_len = hello_data[offset]
            cookie = hello_data[offset + 1:offset + 1 + cookie_len] if cookie_len > 0 else b''

            print("\nClientHello Body:")
            print(f"Version: {client_version.hex()}")
            print(f"Random: {client_random.hex()}")
            print(f"Session ID length: {session_id_len}")
            print(f"Cookie length: {cookie_len}")
            print(f"Cookie: {cookie.hex() if cookie else 'empty'}")

            return {
                'version': client_version,
                'random': client_random,
                'cookie': cookie
            }

        except Exception as e:
            print(f"\nError parsing ClientHello: {e}")
            print(f"Raw data ({len(data)} bytes): {data.hex()}")
            return None

    def create_hello_verify_request(self, cookie):
        """Create HelloVerifyRequest message"""
        # HelloVerifyRequest body
        hvr_body = (
                b'\xfe\xfd' +  # Server version
                struct.pack("!B", len(cookie)) +  # Cookie length
                cookie  # Cookie
        )

        # Add handshake header
        hvr_msg = self.handshake.create_handshake_header(
            msg_type=3,  # HelloVerifyRequest
            length=len(hvr_body),
            seq=0
        ) + hvr_body

        # Add record header
        record = self.record_layer.create_record_header(
            content_type=22,  # Handshake
            length=len(hvr_msg)
        ) + hvr_msg

        return record

    def create_server_hello(self):
        """Create ServerHello message"""
        try:
            # Generate server random if not already set
            if not self.handshake.server_random:
                self.handshake.server_random = os.urandom(HandshakeLayer.SERVER_RANDOM_LENGTH)

            # ServerHello body
            hello_body = (
                    ProtocolVersion.DTLS_1_2 +  # Server version
                    self.handshake.server_random +  # Server random
                    struct.pack("!B", len(self.handshake.session_id)) +  # Session ID length
                    self.handshake.session_id +  # Session ID
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA +  # Selected cipher suite
                    b'\x00'  # Selected compression method
            )

            # Add handshake header
            hello_msg = self.handshake.create_handshake_header(
                msg_type=HandshakeType.SERVER_HELLO,
                length=len(hello_body),
                seq=1
            ) + hello_body

            # Add record header
            record = self.record_layer.create_record_header(
                content_type=ContentType.HANDSHAKE,
                length=len(hello_msg)
            ) + hello_msg

            print(f"Created ServerHello ({len(record)} bytes)")
            print(f"ServerHello content: {record.hex()}")
            return record

        except Exception as e:
            print(f"Error creating ServerHello: {e}")
            traceback.print_exc()
            return None


    def create_server_certificate(self):
        """Create Certificate message"""
        try:
            # Convert the public key to a JSON string
            cert_body = json.dumps(self.pub_key).encode()

            # Add handshake header
            cert_msg = self.handshake.create_handshake_header(
                msg_type=11,  # Certificate
                length=len(cert_body),
                seq=2
            ) + cert_body

            # Add record header
            record = self.record_layer.create_record_header(
                content_type=22,  # Handshake
                length=len(cert_msg)
            ) + cert_msg

            print(f"Created Certificate ({len(record)} bytes)")
            print(f"Certificate content: {record.hex()}")
            return record

        except Exception as e:
            print(f"Error creating certificate: {e}")
            raise

    def create_server_hello_done(self):
        """Create ServerHelloDone message"""
        # Empty body for ServerHelloDone
        done_msg = self.handshake.create_handshake_header(
            msg_type=14,  # ServerHelloDone
            length=0,
            seq=3
        )

        # Add record header
        record = self.record_layer.create_record_header(
            content_type=22,  # Handshake
            length=len(done_msg)
        ) + done_msg

        print(f"Created ServerHelloDone ({len(record)} bytes)")
        return record

    def handle_client_hello(self, packet):
        """Handle ClientHello message"""
        client_ip = packet[IP].src
        client_port = packet[UDP].sport

        try:
            raw_data = packet[Raw].load
            print(f"\nProcessing ClientHello from {client_ip}:{client_port}")
            print(f"Packet length: {len(raw_data)} bytes")

            parsed_hello = self.parse_client_hello(raw_data)
            if not parsed_hello:
                print("Failed to parse ClientHello")
                return False

            if not parsed_hello.get('cookie'):
                print("\nInitial ClientHello (no cookie)")
                cookie = self.cookie_manager.generate_cookie(
                    client_ip, client_port, raw_data
                )
                if not cookie:
                    print("Failed to generate cookie")
                    return False

                print("Sending HelloVerifyRequest")
                time.sleep(1)
                hello_verify = self.create_hello_verify_request(cookie)
                send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(hello_verify))
                return True  # Changed from False to avoid cookie_exchange_failed message
            else:
                print(f"\nProcessing ClientHello with cookie")
                verified = self.cookie_manager.verify_cookie(
                    parsed_hello['cookie'],
                    client_ip,
                    client_port,
                    raw_data
                )

                if verified:
                    print("Cookie verification successful - proceeding with handshake")
                    time.sleep(0.5)
                    return self.send_server_flight(client_ip, client_port)
                else:
                    print("Cookie verification failed - aborting handshake")
                    return False

        except Exception as e:
            print(f"Error handling ClientHello: {e}")
            traceback.print_exc()
            return False

    def send_server_flight(self, client_ip, client_port):
        """Send server's flight of handshake messages"""
        try:
            print("\nPreparing server flight...")

            # Create and send ServerHello
            server_hello = self.create_server_hello()
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(server_hello))
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(server_hello))
            print("Sent ServerHello successfully")
            time.sleep(1)  # Increased delay between messages

            # Create and send Certificate
            certificate = self.create_server_certificate()
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(certificate))
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(certificate))
            print("Sent Certificate successfully")
            time.sleep(1)  # Increased delay between messages

            # Create and send ServerHelloDone
            server_hello_done = self.create_server_hello_done()
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(server_hello_done))
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(server_hello_done))
            print("Sent ServerHelloDone successfully")

            return True

        except Exception as e:
            print(f"Error sending server flight: {e}")
            traceback.print_exc()
            return False

    def send_client_flight(self):
        """Send client's flight of messages"""
        try:
            print("\nPreparing client flight...")

            # Send Certificate
            print("Sending Certificate...")
            cert_record = self.create_client_certificate()
            response = self.send_packet(cert_record)
            if not response:
                print("No response to Certificate")
                return False
            time.sleep(0.2)  # Small delay between messages

            # Send ClientKeyExchange
            print("Sending ClientKeyExchange...")
            key_exchange = self.create_client_key_exchange()
            response = self.send_packet(key_exchange)
            if not response:
                print("No response to ClientKeyExchange, retrying")
                response = self.send_packet(key_exchange)
                if not response:
                    return False
            time.sleep(0.2)

            # Send ChangeCipherSpec
            print("Sending ChangeCipherSpec...")
            change_cipher_spec = self.record_layer.create_record_header(
                content_type=20,  # ChangeCipherSpec
                length=1
            ) + b'\x01'  # Change cipher spec message

            self.record_layer.new_epoch()  # Increment epoch before sending ChangeCipherSpec
            response = self.send_packet(change_cipher_spec)
            if not response:
                print("No response to ChangeCipherSpec")
                return False
            time.sleep(0.1)

            # Send Finished
            print("Sending Finished...")
            finished = self.create_finished_message()
            response = self.send_packet(finished)
            if not response:
                print("No response to Finished")
                return False

            # Process server's Finished message
            if not self.verify_server_finished(response):
                print("Failed to verify server's Finished message")
                return False

            print("Client flight completed successfully")
            return True

        except Exception as e:
            print(f"Error sending client flight: {e}")
            traceback.print_exc()
            return False

    def process_client_key_exchange(self, data):
        """Process client key exchange with NTRU"""
        try:
            # Skip headers
            key_data = data[RecordLayer.HEADER_LENGTH + HandshakeLayer.HEADER_LENGTH:]

            # Decrypt using NTRU
            self.pre_master_secret = self.challenge.decrypt(key_data)

            # Derive master secret
            if self.derive_master_secret():
                print("Master secret derived successfully")
                return True
            return False

        except Exception as e:
            print(f"Error processing client key exchange: {e}")
            traceback.print_exc()
            return False

    def process_client_finished(self, data):
        """Process client finished message"""
        try:
            # Skip headers and verify finished message
            verify_data = data[25:]
            print(f"Received verify data length: {len(verify_data)}")
            # Here you would implement finished message verification
            return True
        except Exception as e:
            print(f"Error processing client finished: {e}")
            return False

    def run(self):
        """Main server loop"""
        print("\nWaiting for DTLS connections...")

        while True:
            try:
                # Wait for initial ClientHello
                pkt = sniff(filter=f"udp port {self.server_port}", count=1)[0]
                if not Raw in pkt:
                    continue

                client_ip = pkt[IP].src
                client_port = pkt[UDP].sport

                data = pkt[Raw].load
                content_type = data[0]
                handshake_type = data[13] if content_type == ContentType.HANDSHAKE and len(data) > 13 else None

                # If this is a ClientHello message
                if content_type == ContentType.HANDSHAKE and handshake_type == HandshakeType.CLIENT_HELLO:
                    print(f"\nReceived connection from {client_ip}:{client_port}")

                    # Initialize new connection state
                    self.state = DTLSState.INITIAL
                    self.current_client = (client_ip, client_port)

                    # Handle ClientHello and cookie exchange
                    result = self.handle_client_hello(pkt)
                    if not result:
                        print("Handshake failed")
                        continue


                # Handle client's flight messages
                elif self.state >= DTLSState.SERVER_HELLO_DONE_WAIT:
                    print("\nReceived client flight message")
                    if not self.handle_client_flight(client_ip, client_port):
                        print("Failed to process client flight")
                        continue

            except Exception as e:
                print(f"Error in main loop: {e}")
                traceback.print_exc()
                continue

    def handle_client_flight(self, client_ip, client_port):
        """Handle client's flight of messages"""
        try:
            print("\nWaiting for client's flight...")

            # Collect all flight messages
            client_flight = sniff(
                filter=f"udp src port {client_port} and dst port {self.server_port}",
                timeout=10,
                count=4  # Certificate, KeyExchange, ChangeCipherSpec, Finished
            )

            if not client_flight:
                print("No client flight received")
                return False

            print(f"Received {len(client_flight)} messages from client")

            certificate_received = False
            key_exchange_received = False
            change_cipher_spec_received = False
            finished_received = False

            for pkt in client_flight:
                if not Raw in pkt:
                    continue

                data = pkt[Raw].load
                if len(data) < RecordLayer.HEADER_LENGTH:
                    continue

                content_type = data[0]
                if content_type == ContentType.HANDSHAKE:
                    handshake_data = data[RecordLayer.HEADER_LENGTH:]
                    if len(handshake_data) < HandshakeLayer.HEADER_LENGTH:
                        continue

                    msg_type = handshake_data[0]
                    print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")


                    if msg_type == HandshakeType.CERTIFICATE:
                        if self.process_client_certificate(data):
                            certificate_received = True
                            print("Certificate processed successfully")
                            self.send_handshake_ack(client_ip, client_port)

                    elif msg_type == HandshakeType.CLIENT_KEY_EXCHANGE:
                        if self.process_client_key_exchange(data):
                            key_exchange_received = True
                            print("KeyExchange processed successfully")
                            self.send_handshake_ack(client_ip, client_port)

                elif content_type == ContentType.CHANGE_CIPHER_SPEC:
                    if self.process_change_cipher_spec(data):
                        change_cipher_spec_received = True
                        print("ChangeCipherSpec processed successfully")
                        self.record_layer.new_epoch()

                elif content_type == ContentType.HANDSHAKE and msg_type == HandshakeType.FINISHED:
                    if self.process_client_finished(data):
                        finished_received = True
                        print("Finished message processed successfully")
                        self.send_server_finished(client_ip, client_port)

            print("\nClient flight summary:")
            print(f"Certificate received: {certificate_received}")
            print(f"KeyExchange received: {key_exchange_received}")
            print(f"ChangeCipherSpec received: {change_cipher_spec_received}")
            print(f"Finished received: {finished_received}")

            return certificate_received  # For now, just check certificate receipt

        except Exception as e:
            print(f"Error handling client flight: {e}")
            traceback.print_exc()
            return False

    def send_server_finished(self, client_ip, client_port):
        """Send server's Finished message"""
        try:
            finished = self.create_handshake_finished()
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(finished))
        except Exception as e:
            print(f"Error sending server Finished: {e}")

    def send_handshake_ack(self, client_ip, client_port):
        """Send handshake acknowledgment"""
        try:
            handshake_ack = self.create_handshake_finished()
            send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(handshake_ack))
        except Exception as e:
            print(f"Error sending handshake ack: {e}")

    def process_change_cipher_spec(self, data):
        """Process ChangeCipherSpec message"""
        try:
            if len(data) < 14:  # Record header + ChangeCipherSpec
                return False

            # Verify it's a proper ChangeCipherSpec
            if data[0] != 20 or data[13] != 1:
                return False

            print("Received ChangeCipherSpec")
            return True

        except Exception as e:
            print(f"Error processing ChangeCipherSpec: {e}")
            return False


    def process_client_certificate(self, data):
        """Process client certificate"""
        try:
            cert_body = data[25:]
            client_cert = json.loads(cert_body.decode())
            print(f"Received client certificate: {client_cert}")
            return True
        except Exception as e:
            print(f"Error processing client certificate: {e}")
            return False

    def handle_application_data(self, client_ip, client_port):
        """Handle application data phase"""
        try:
            print("\nReady for application data...")

            while True:
                pkt = sniff(
                    filter=f"udp and host {client_ip}",  # Simplified filter
                    count=1,
                    timeout=30
                )

                if not pkt:
                    raise DTLSError("Connection timeout")

                if Raw in pkt[0]:
                    data = pkt[0][Raw].load
                    if len(data) > 13 and data[0] == 23:  # Application Data
                        app_data = data[13:]  # Skip record header
                        print(f"Received application data: {app_data.decode()}")

                        # Echo the data back
                        response = self.record_layer.create_record_header(
                            content_type=23,  # Application Data
                            length=len(app_data)
                        ) + app_data

                        send(IP(dst=client_ip) / UDP(sport=self.server_port, dport=client_port) / Raw(response))
                        self.record_layer.increment_seq()

        except DTLSError as e:
            print(f"DTLS Error: {e}")
            raise
        except Exception as e:
            print(f"Error handling application data: {e}")
            traceback.print_exc()
            raise

    def create_handshake_finished(self):
        """Create a Finished message"""
        verify_data = os.urandom(12)  # Example verify data

        finished_msg = self.handshake.create_handshake_header(
            msg_type=20,  # Finished
            length=len(verify_data),
            seq=4
        ) + verify_data

        record = self.record_layer.create_record_header(
            content_type=22,  # Handshake
            length=len(finished_msg)
        ) + finished_msg

        return record


if __name__ == "__main__":
    server = DTLSServer("0.0.0.0", 4433)
    server.run()
