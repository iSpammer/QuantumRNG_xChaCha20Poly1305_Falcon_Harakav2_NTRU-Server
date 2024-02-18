# Import scapy and random modules
import base64
import hashlib
import os

import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305

from scapy.all import *
import random

from CA_CONNECTION import request_handler
from NTRU import ntru
from scapy.layers.inet import IP
import ast
import pyspx.haraka_256f
import pyspx.haraka_128s
from harakav2 import pad_message, haraka512256
from falcon import falcon
from QRNG_6QUBIT import QRNG_GEN
import numpy as np
import numpy as np

data_server = np.load('server_cert.npy',allow_pickle='TRUE').item()
pub_key = data_server['pub_key_s_h']
print(data_server)
priv_key_sf = data_server['sk_f']
priv_key_sg = data_server['sk_g']
# print("country ", country)
# print("state_code ", state_code)
# print("state ", state)
# print("org ", org)
# print("org_unit ", org_unit)
# print("cname ", cname)
# print("email ", email)
print("pub_key_s_h ", (pub_key))
print("priv_key_sf ", (priv_key_sf))
print("priv_key_sg ", (priv_key_sg))

Challenge = ntru.Ntru(7, 29, 491531)
Challenge.genPublicKey(priv_key_sf,priv_key_sg, 2)


# Define the server IP and port
server_ip = "192.168.68.139"
server_port = 4449

server_qrng = b""
client_qrng = b""

class EncryptedTCP(Packet):
    name = "EncryptedTCP"
    fields_desc = [

        StrFixedLenField("sport", b"\x00\x00\x00\x00\x00", 5),
        # encrypted source port with padding
        StrFixedLenField("dport", b"\x00\x00\x00\x00\x00", 5),
        # encrypted destination port with
        IntField("seq", 0),  # sequence number
        IntField("ack", 0),  # acknowledgement number
        BitField("dataofs", None, 4),  # data offset
        BitField("reserved", 0, 3),  # reserved bits
        FlagsField("flags", 0x2, 9, "FSRPAUECN"),  # flags
        ShortField("window", 8192),  # window size
        XShortField("chksum", None),  # checksum
        ShortField("urgptr", 0),  # urgent pointer
        PacketListField("options", []),  # options
        # StrFixedLenField("EncHeader", b"head", 4),
        # StrFixedLenField("EncTag", b"Tag1", 4),
        # StrFixedLenField("EncNonce", b"Nonce", 12),
    ]



# Bind the custom layer to the IP layer in top-down direction
bind_layers(IP, EncryptedTCP, proto=99)

# TODO update QRNG/CLientNONCE with each message
def sign_fn(payload, server_qrng_old, header, client_qrng_new):
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
    # payload = cipher.encrypt(qrng, payload)
    return result, QRNG_GEN("server")


def check_signature(payload, client_qrng_old, challenge=False):
    if challenge:
        print("mafrod y5osh hena ",payload)
        payload = payload.decode()
        payload = payload.split("<|>")

        plaintext = Challenge.decrypt(ast.literal_eval(payload[0]))
        print(plaintext)
        if plaintext == [1, 0, 1, 0, 1, 2, 1]:
            return plaintext, ast.literal_eval(payload[1]), True, QRNG_GEN("client")
        else:
            print("MOSHKEALLLALALALA")
            return False
    else:
        try:
            b64 = json.loads(payload)
            jk = ['nonce', 'header', 'ciphertext', 'tag']
            jv = {k: b64decode(b64[k]) for k in jk}

            if jv['nonce'] == client_qrng_old:
                print("NONCE VERIFIED FROM CLIENT")
            else:
                print("ERROR MESSAGE COULD BE TAMPERED")
            cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            # print("The message was: " + plaintext.decode())
            blockhash, sign_str, pk_arr = plaintext.split(b'<|>')
            sign_str = bytes(sign_str)
            # dec_hash = dec_hash.decode("UTF-8")
            print("dec hash : ", blockhash)

            pk_fn = falcon.PublicKey(n=32, h=list(struct.unpack('>' + 'h' * (len(pk_arr) // 2), pk_arr)))
            # print("verification status = ", pyspx.haraka_256f.verify(dec_hash, signature, pub_key))
            check = pk_fn.verify(blockhash, bytes(sign_str))
            # Create a message of around 100 bytes
            print("verification status " + str(check))

            # dec_hash_sign = cipher.decrypt(qrng, payload)
            print("decryped hash+sig ", blockhash)
            return blockhash, check, QRNG_GEN("client")
        except (ValueError, KeyError):
            print("Incorrect decryption")


# Create an instance of the Ntru class with the parameters N=7, p=29 and q=491531
print("Server Will Generate his Public Key using Parameters")
print("N=7,p=29 and q=491531")
Bob = ntru.Ntru(7, 29, 491531)

# Bob generates a random key pair
f = [1, 1, -1, 0, -1, 1]
g = [-1, 0, 1, 1, 0, 0, -1]
d = 2
print("f(x)= ", f)
print("g(x)= ", g)
print("d   = ", d)
Bob.genPublicKey(f, g, 2)
pub_key = Bob.getPublicKey()
print("Public Key Generated by Bob: ", pub_key)


# Wait for the SYN packet from the client
syn = sniff(filter=f"ip and host {server_ip}", count=1)[0]

# Get the destination IP and port from the SYN packet
client_ip = syn[IP].src

addr = [client_ip, 0]

ip_pkt = IP(dst=addr[0], proto=99)
# Create a TCP SYN-ACK packet with the client as the destination
syn_ack =  ip_pkt/ EncryptedTCP(flags="SA", ack=syn.seq + 1)

# Send the SYN-ACK packet and receive the TCP ACK packet from the client
ack = sr1(syn_ack)
print("TCP Hanfshake successful")

# Send the parameters and the public key to the client as a tuple of bytes
params = ','.join(map(str, [Bob.N, Bob.p, Bob.q])).encode()
pub_bytes = str(pub_key)

msg1 = params + b'|' + bytes(pub_bytes.encode())
# Create a TCP packet with the message as the payload
pkt1 = ip_pkt / EncryptedTCP( flags="PA") / msg1
print("sending pub key", pkt1.show())
send(pkt1)
# reply1 = sr1(pkt1)
# Send the packet and receive the reply text of 700 bytes from the client
reply1 = sniff(filter=f"ip and host {server_ip}", count=1)[0]
print("sent, waiting for cipher text from client")
# Check if the reply length is 700 bytes
if len(reply1[Raw].load) >= 0:
    print("received ct = ", ast.literal_eval(reply1[Raw].load.decode("UTF-8")))

    decrypt_msg = Bob.decrypt(ast.literal_eval(reply1[Raw].load.decode("UTF-8")))
    print("Decrypted Message          : ", decrypt_msg)

    # Bob uses the decrypted message as the shared secret and hashes it with SHA-256
    # shared_secret = hashlib.sha256(bytes(decrypt_msg)).hexdigest()
    decrypt_msg = pad_message(bytes(decrypt_msg))
    shared_secret = bytes(haraka512256(decrypt_msg))
    print("Shared Secret              : ", shared_secret)

    # TODO implement Blockchain/SSI and add hash/verifier
    # Create a message of around 100 by
    # server_qrng = b'\xb8\x08\x9c\xd2\xea\xbe\xf7\x1e\xac\xf1\xd6$'
    server_qrng =  QRNG_GEN("server init")

    client_qrng = QRNG_GEN("client init")
    print("SENDINGx ",data_server['pub_key_s_h'], "OF TYPE ",type(pub_key))

    msg2 = json.dumps(data_server['pub_key_s_h'])
    msg2 = bytes(msg2, 'utf-8')
    # msg2 = b"This is a message of around 100 bytes.\n"
    msg2, server_qrng = sign_fn(msg2, server_qrng, header=b"server_hash", client_qrng_new=client_qrng)

    # Create a TCP packet with the message as the payload
    pkt2 = ip_pkt / EncryptedTCP( flags="PA") / msg2
    # Send the packet and receive the message of around 100 bytes from the client
    print("sending hash", msg2)
    # msg3 = sr1(pkt2)

    send(pkt2)
    # Send the packet and receive the reply text of 700 bytes from the client
    msg3 = sniff(filter=f"ip and host {server_ip}", count=1)[0]
    solved_challenge, client_hash, verif, client_qrng = check_signature(msg3[Raw].load, client_qrng_old=client_qrng, challenge=True)

    print("receiving hash >>>", client_hash)
    print("Reply from hash: " + str(client_hash))
    print("PKI HASH VERIFICATION STATUS ", request_handler.get_request(solved_challenge=solved_challenge, server_pub=(client_hash), ip_pkt=ip_pkt, server_ip="192.168.0.18"))

    # enc_qrng_nonce = cipher.encrypt(enc_init_nonce, qrng_nonce)
    # TODO add encrypted qrng so that the client's first message couldn't be tampered
    pkt3 = ip_pkt / EncryptedTCP(flags="A")

    print("sending ack of hash")
    send(pkt3)
    send(pkt3)
    print("done, starting comm with client")

    i = 0
    # Enter a loop to exchange messages with the client until bye is sent or received
    while True:
        print("receiving...")
        # Receive a message from the client
        msg4 = sniff(filter=f"ip and dst 192.168.68.139 and src 192.168.68.143", count=1)[0]
        print("got msg4", msg4.show())
        # Check if the message contains bye
        if msg4[EncryptedTCP].flags == "F" or msg4[EncryptedTCP].flags == "FA":
            print("finalising")
            # Receive the TCP FIN packet from the client
            # fin = s.recv()
            # Create a TCP FIN-ACK packet to acknowledge the FIN packet
            fin_ack = IP(dst=addr[0]) / EncryptedTCP(flags="FA")
            # Send the FIN-ACK packet and receive the TCP ACK packet from the client
            send(fin_ack)
            # ack_fin = sniff(filter=f"ip and host {server_ip}", count=1)[0]
            # Close the connection and exit the loop
            # s.close()
            break
        else:
            client_msg, verif, client_qrng = check_signature(payload=msg4[Raw].load, client_qrng_old=client_qrng)
            # Create a reply message based on the client message
            reply2 = "Hello client, you said: " + client_msg.decode("UTF-8")
            print("replying")
            reply2, server_qrng = sign_fn(payload=reply2.encode(), server_qrng_old=server_qrng,
                             header=b"client_reply" + str(random.randint(-99, 99)).encode(), client_qrng_new=client_qrng)
            # Create a TCP packet with the reply message as the payload
            flag = "PA"
            if i == 0:
                flag = "P"
            pkt3 = IP(dst=addr[0]) / EncryptedTCP(flags=flag,) / reply2
            # Send the packet to the client
            print("sent reply")
            send(pkt3)
            i = i + 1

else:
    # Print an error message if the reply length is not 700 bytes
    print("Error: The reply from client is not 700 bytes.")