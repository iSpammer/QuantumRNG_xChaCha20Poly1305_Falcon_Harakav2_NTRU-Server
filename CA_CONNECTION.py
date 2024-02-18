# Import the requests module
import ast
import base64
import random
import sys

import requests
from scapy.packet import Raw
from scapy.sendrecv import send, sniff

from NTRU import ntru
from encrypted_tcp import EncryptedTCP
from falcon import falcon
from harakav2 import haraka512256
from Crypto.Cipher import ChaCha20_Poly1305
import struct
from base64 import b64encode, b64decode
import json
import numpy as np

# TODO Remove this line
# server_sk = np.load('server_ca.npz')['x'][8]

data_ca = np.load('server_cert.npy',allow_pickle='TRUE').item()
print(data_ca)
print("country ",data_ca['country'])
print("state_code ",data_ca['state_code'])
print("state ",data_ca['state'])
print("org ",data_ca['org'])
print("org_unit ",data_ca['org_unit'])
print("cname ",data_ca['cname'])
print("email ",data_ca['email'])
print("pub_key_s_h ",data_ca['pub_key_s_h'])

country = data_ca['country']
state_code = data_ca['state_code']
state= data_ca['state']
org = data_ca['org']
org_unit = data_ca['org_unit']
cname = data_ca['cname']
email = data_ca['email']
pub_key_s_h = data_ca['pub_key_s_h']
priv_key_sf = data_ca['sk_f']
priv_key_sg = data_ca['sk_g']


print("country ", country)
print("state_code ", state_code)
print("state ", state)
print("org ", org)
print("org_unit ", org_unit)
print("cname ", cname)
print("email ", email)
print("pub_key_s_h_xd ", (pub_key_s_h))
print("priv_key_sf ", (priv_key_sf))
print("priv_key_sg ", (priv_key_sg))

Challenge = ntru.Ntru(7, 29, 491531)
Challenge.genPublicKey(priv_key_sf,priv_key_sg, 2)

def sign_fn(shared_secret, payload):
    challenge_creator = ntru.Ntru(7, 29, 491531)
    challenge_creator.setPublicKey(shared_secret)
    ciphertext = challenge_creator.encrypt(payload, [random.choice([-1, 0, 1]) for _ in range(7)])

    result = ciphertext

    # payload = cipher.encrypt(qrng, payload)
    return result


def check_signature(payload):
    # try:
    print("mafrod y5osh hena ")
    b64 = json.loads(payload)

    plaintext = Challenge.decrypt(b64['ciphertext'])
    if plaintext == [1, 0, 1, 0, 1, 1, 2]:
        return True
    else:
        return False

# Define a class that handles the requests
class RequestHandler:

    # Define the constructor that takes the server address and port as arguments
    def __init__(self, server_address, server_port):
        # Store the server address and port as attributes
        self.server_address = server_address
        self.server_port = server_port


    # Define a method that sends a get request
    def get_request(self, solved_challenge, server_pub, ip_pkt, server_ip):
        print("hab3at lel pki ", server_pub)
        # Send a get request to the server
        lnk = f"https://{self.server_address}:6000/chain_details_get"
        print("rabet ", lnk)
        data = {"hashidd": server_pub}
        response = requests.post(lnk, json=json.dumps(data), verify=False)

        # Print the status code and the content of the response
        print(f"Status code: {response.status_code}")
        if response.status_code != 200:
            print("COMMUNICATION FAILED!")
            return False
        print(f"Content: {response.text}")
        # Import the json module

        # Define the output as a string
        resp = response.text.strip("\\")
        print("asd! ", resp)
        # Parse the output as a JSON object
        output = json.loads(response.text)

        # Get the chain and the length from the output
        chain = output["chain"]
        length = output["len"]

        # Print the chain length
        print(f"The chain length is {length}")
        # if(length > 1)
        #     return True;
        # Loop through the chain
        #TODO fix maby5oshesh hena moshkla fl pub cert ????
        for block in chain:
            # Parse the block as a JSON object
            block = json.loads(block)

            # Get the block details
            block_number = block["block_number"]
            transactions = block["transactions"]
            previous_hash = block["previous_hash"]
            nonce = block["nonce"]
            hashid = block["hashid"]
            timestamp = block["timestamp"]

            pub_key_s_h_sr = transactions["pub_key_s_h"]
            # pub_key_s_h = binascii.b2a_base64(pub_key_s_h).decode('ascii')

            # Print the block details
            print(f"Block number: {block_number}")
            print(f"Transactions: {transactions}")
            print(f"Previous hash: {previous_hash}")
            print(f"Nonce: {nonce}")
            print(f"Hashid: {hashid}")
            print(f"Timestamp: {timestamp}")
            print(f"Public Key from PKI{pub_key_s_h_sr}")
            print(f"Public Key type {type(pub_key_s_h_sr)}")
            print(f"server Key {type(server_pub)}")

            print("pub received from server", server_pub)

            print("pub received from PKI", pub_key_s_h_sr)

            print()
            #TODO MUST BE EQUAL
            if server_pub != pub_key_s_h_sr:

                # Decode the ASCII bytes using binascii.a2b_base64()
                print("restored_bytes2", server_pub)
                print("sending random challenge to protect from replay attacks")
                challenge = sign_fn(shared_secret=server_pub, payload=solved_challenge)
                print("sending ",challenge)
                challenge_pkt = ip_pkt / EncryptedTCP(flags="PA") / str(challenge)

                send(challenge_pkt)

                # challenge_rply = sniff(filter=f"ip and host {server_ip}", count=1)[0]
                # print("challenge reply msg : ", challenge_rply[Raw].load)

                # msg4 = sniff(filter=f"ip and host {client_ip}", count=1)[0]
                msg4 = ip_pkt
                return True
            else:
                print('UNVERIFIABLE HASH TERMINATING NOW')
                sys.exit()
                return False



        #todo sheel l7ad hena
    # Define a method that does both the post and the get requests
    def do_both(self, data):
        # Call the post request method with the data
        # self.post_request(data)

        # Call the get request method
        self.get_request()


# Create an instance of the RequestHandler class with the server address and port
request_handler = RequestHandler("192.168.0.18", 5000)

# Define the data to send
data = {"var1": "foo", "var2": "bar", "var3": "baz"}

# Call the do_both method with the data
# print(request_handler.get_request(ast.literal_eval("[9513, 8537, 932, 4492, 2761, 11599, 10238, 5271, 1619, 64, 1122, 11931, 2474, 10832, 9653, 10723, 2991, 2071, 10133, 6203, 814, 6893, 12258, 10357, 6798, 3856, 9597, 5809, 7453, 3553, 12020, 99]")))
