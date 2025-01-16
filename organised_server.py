import ast
import base64
import hashlib
import json
import os
import random
import struct
from base64 import b64encode, b64decode

import numpy as np
from Crypto.Cipher import ChaCha20_Poly1305
from scapy.all import *
from scapy.layers.inet import IP

from NTRU import ntru
from falcon import falcon
from harakav2 import pad_message, haraka512256
from QRNG_6QUBIT import QRNG_GEN

# Load server certificate data
data_server = np.load('server_cert.npy', allow_pickle='TRUE').item()
pub_key = data_server['pub_key_s_h']
priv_key_sf = data_server['sk_f']
priv_key_sg = data_server['sk_g']

# Initialize NTRU for key exchange
Challenge = ntru.Ntru(7, 29, 491531)
Challenge.genPublicKey(priv_key_sf, priv_key_sg, 2)

# Server configuration
SERVER_IP = "192.168.68.139"
SERVER_PORT = 4449

# Global variables
shared_secret = None
server_qrng = None
client_qrng = None


class EncryptedTCP(Packet):
    name = "EncryptedTCP"
    fields_desc = [
        StrFixedLenField("sport", b"\x00\x00\x00\x00\x00", 5),
        StrFixedLenField("dport", b"\x00\x00\x00\x00\x00", 5),
        IntField("seq", 0),
        IntField("ack", 0),
        BitField("dataofs", None, 4),
        BitField("reserved", 0, 3),
        FlagsField("flags", 0x2, 9, "FSRPAUECN"),
        ShortField("window", 8192),
        XShortField("chksum", None),
        ShortField("urgptr", 0),
        PacketListField("options", []),
    ]


# Bind the custom layer to the IP layer
bind_layers(IP, EncryptedTCP, proto=99)


def sign_fn(payload, server_qrng_old, header, client_qrng_new):
    """
    Sign and encrypt the payload using ChaCha20_Poly1305 and Falcon
    """
    global shared_secret
    cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=server_qrng_old)
    cipher.update(header)
    secret_key_sign = falcon.SecretKey(32)
    public_key_sign = falcon.PublicKey(secret_key_sign)
    sign_str = secret_key_sign.sign(payload)
    pk_arr = public_key_sign.h
    pk_arr = struct.pack('>' + 'h' * len(pk_arr), *pk_arr)
    payload = payload + b"<|>" + sign_str + b"<|>" + pk_arr + b"<|>" + client_qrng_new

    ciphertext, tag = cipher.encrypt_and_digest(payload)
    jk = ['nonce', 'header', 'ciphertext', 'tag']
    jv = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
    result = json.dumps(dict(zip(jk, jv)))
    return result, QRNG_GEN("server")


def check_signature(payload, client_qrng_old, challenge=False):
    """
    Verify the signature and decrypt the payload
    """
    global shared_secret
    if challenge:
        payload = payload.decode().split("<|>")
        plaintext = Challenge.decrypt(ast.literal_eval(payload[0]))
        if plaintext == [1, 0, 1, 0, 1, 2, 1]:
            return plaintext, ast.literal_eval(payload[1]), True, QRNG_GEN("client")
        else:
            return False
    else:
        try:
            b64 = json.loads(payload)
            jk = ['nonce', 'header', 'ciphertext', 'tag']
            jv = {k: b64decode(b64[k]) for k in jk}

            if jv['nonce'] == client_qrng_old:
                print("NONCE VERIFIED FROM CLIENT")
            else:
                print("ERROR: MESSAGE COULD BE TAMPERED")

            cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

            blockhash, sign_str, pk_arr = plaintext.split(b'<|>')
            sign_str = bytes(sign_str)

            pk_fn = falcon.PublicKey(n=32, h=list(struct.unpack('>' + 'h' * (len(pk_arr) // 2), pk_arr)))
            check = pk_fn.verify(blockhash, bytes(sign_str))

            print("Verification status:", check)
            print("Decrypted hash:", blockhash)

            return blockhash, check, QRNG_GEN("client")
        except (ValueError, KeyError):
            print("Incorrect decryption")


def perform_key_exchange(client_packet):
    global shared_secret
    # Generate NTRU key pair
    server_public_key = Challenge.getPublicKey()

    # Send server's public key to the client
    server_public_key_packet = IP(dst=client_packet[IP].src) / EncryptedTCP(flags="PA") / str(server_public_key)
    send(server_public_key_packet)

    # Receive client's encrypted message
    client_encrypted_message = sniff(filter=f"ip and host {SERVER_IP}", count=1)[0]

    # Check if the packet has a Raw layer
    if Raw in client_encrypted_message:
        try:
            decrypted_message = Challenge.decrypt(ast.literal_eval(client_encrypted_message[Raw].load.decode("UTF-8")))

            # Use the decrypted message as the shared secret
            shared_secret = bytes(haraka512256(pad_message(bytes(decrypted_message))))
            print("Shared Secret:", shared_secret.hex())
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return False
    else:
        print("Received packet doesn't contain payload data")
        return False

    return True

def send_server_certificate(client_ip):
    """
    Send the server's certificate to the client
    """
    global server_qrng, client_qrng
    server_qrng = QRNG_GEN("server init")
    client_qrng = QRNG_GEN("client init")

    certificate = json.dumps(data_server['pub_key_s_h'])
    certificate = bytes(certificate, 'utf-8')

    signed_certificate, server_qrng = sign_fn(certificate, server_qrng, header=b"server_hash",
                                              client_qrng_new=client_qrng)

    certificate_packet = IP(dst=client_ip) / EncryptedTCP(flags="PA") / signed_certificate
    send(certificate_packet)


def verify_client_certificate(client_packet):
    """
    Verify the client's certificate
    """
    global client_qrng
    client_certificate = client_packet[Raw].load
    solved_challenge, client_hash, verif, client_qrng = check_signature(client_certificate, client_qrng_old=client_qrng,
                                                                        challenge=True)

    if verif:
        print("Client certificate verified")
        # Here you would typically check the client_hash against the blockchain PKI
        # For this example, we'll assume it's valid
        return True
    else:
        print("Client certificate verification failed")
        return False


def handle_client_connection(client_packet):
    global server_qrng, client_qrng, shared_secret

    # Step 1: TCP handshake is handled by Scapy

    # Step 2: Send server's NTRU public key
    server_public_key = Challenge.getPublicKey()
    server_public_key_packet = IP(dst=client_packet[IP].src) / EncryptedTCP(
        flags="PA") / f"{Challenge.N},{Challenge.p},{Challenge.q}|{server_public_key}"
    send(server_public_key_packet)

    # Step 3 & 4: Receive client's encrypted message
    client_encrypted_message = sniff(filter=f"ip and host {SERVER_IP}", count=1)[0]
    if Raw not in client_encrypted_message:
        print("Error: No encrypted message received from client")
        return

    # Step 5: Decrypt message and calculate shared secret
    try:
        decrypted_message = Challenge.decrypt(ast.literal_eval(client_encrypted_message[Raw].load.decode("UTF-8")))
        shared_secret = bytes(haraka512256(pad_message(bytes(decrypted_message))))
        print("Shared Secret:", shared_secret.hex())
    except Exception as e:
        print(f"Error in key exchange: {e}")
        return

    # Step 6: Send server's certificate
    server_qrng = QRNG_GEN("server init")
    client_qrng = QRNG_GEN("client init")
    certificate = json.dumps(data_server['pub_key_s_h'])
    certificate = bytes(certificate, 'utf-8')
    signed_certificate, server_qrng = sign_fn(certificate, server_qrng, header=b"server_hash",
                                              client_qrng_new=client_qrng)
    certificate_packet = IP(dst=client_packet[IP].src) / EncryptedTCP(flags="PA") / signed_certificate
    send(certificate_packet)

    # Step 7: Receive and verify client's certificate
    client_certificate = sniff(filter=f"ip and host {SERVER_IP}", count=1)[0]
    if Raw not in client_certificate:
        print("Error: No client certificate received")
        return
    solved_challenge, client_hash, verif, client_qrng = check_signature(client_certificate[Raw].load,
                                                                        client_qrng_old=client_qrng, challenge=True)
    if not verif:
        print("Client certificate verification failed")
        return

    # Step 8: Enter communication loop
    while True:
        client_message = sniff(filter=f"ip and host {SERVER_IP}", count=1)[0]

        if client_message[EncryptedTCP].flags == "F" or client_message[EncryptedTCP].flags == "FA":
            print("Client closing connection")
            fin_ack = IP(dst=client_message[IP].src) / EncryptedTCP(flags="FA")
            send(fin_ack)
            break

        if Raw not in client_message:
            print("Error: Received empty message from client")
            continue

        decrypted_message, verif, client_qrng = check_signature(client_message[Raw].load, client_qrng_old=client_qrng)

        if verif:
            print("Received message:", decrypted_message.decode("UTF-8"))

            reply = f"Hello client, you said: {decrypted_message.decode('UTF-8')}"
            encrypted_reply, server_qrng = sign_fn(reply.encode(), server_qrng_old=server_qrng,
                                                   header=b"server_reply", client_qrng_new=client_qrng)

            reply_packet = IP(dst=client_message[IP].src) / EncryptedTCP(flags="PA") / encrypted_reply
            send(reply_packet)
        else:
            print("Message verification failed")


# Make sure these functions are defined: QRNG_GEN, sign_fn, check_signature

def main():
    print(f"Server starting on {SERVER_IP}:{SERVER_PORT}")
    sniff(filter=f"ip and host {SERVER_IP}", prn=handle_client_connection)


if __name__ == "__main__":
    main()
