import base64
import chacha20poly1305
import pyzstd
import zstd
from scapy.all import *
import random

import base128
from scapy.layers.inet import *

# import frodokem
from PQCryptoLWEKE.python3 import frodokem
# set up IP and TCP headers
src_ip = "192.168.68.139"
src_port = 4449
frodo = frodokem.FrodoKEM(variant="FrodoKEM-1344-AES")

compressor = pyzstd.ZstdCompressor()

pub_, sec = frodo.kem_keygen()
pub = frodo.encode(pub_)

print("len 1", len(pub_))
print("len 2", len(pub))
print("pub is ",pub)
def fragment_message(message, client_port, mtu=1000):
    # Calculate the number of fragments needed
    num_fragments = (len(message) + mtu - 1) // mtu
    # Create a list of fragments
    fragments = []
    # Loop through each fragment
    for i in range(num_fragments):
        # Get the start and end index of the fragment
        start = i * mtu
        end = min((i + 1) * mtu, len(message))
        # Create a packet with the fragment as payload
        packet = IP(dst=client_ip, flags="MF") / TCP(dport=client_port, sport=src_port) / Raw(load=message[start:end])
        # Add the packet to the list of fragments
        fragments.append(packet)
    # Return the list of fragments
    return fragments

# Create a TCP socket
s = conf.L3socket()

# Wait for the SYN packet from the client
syn = sniff(filter=f"tcp and host {src_ip} and port {src_port} and tcp[tcpflags] & tcp-syn != 0", count=1)[0]

# Get the destination IP and port from the SYN packet
client_ip = syn[IP].src
client_port = syn[TCP].sport

# Create the SYN-ACK packet
syn_ack = IP(dst=client_ip) / TCP(sport=src_port, dport=client_port, flags="SA", seq=RandNum(0, 2 ** 32), ack=syn.seq + 1,
                               window=syn.window, options=syn.options)

# Send the SYN-ACK packet and receive the ACK packet
ack = s.sr1(syn_ack)
qrng = b""
# Check if the ACK packet has the expected sequence number
if ack.seq == syn_ack.ack:
    # Print a success message
    print("Connection established")
    qrng = ack[Raw].load
else:
    # Print an error message and exit
    print("Error: TCP Hanfshake expected seq {}, got {}".format(syn_ack.ack, ack.seq))
    sys.exit(1)

print("nonce for the session is ",qrng)
# encoded_pub = base64.b64encode(pub)
# Create a large response packet of 12k bytes
# create a TCP data packet with the message to send to the server
server_fragments = fragment_message(pub, client_port=client_port)
max_fr = len(server_fragments)
fr = None

print("starting frags")
for i, fragment in enumerate(server_fragments):
    fr = fragment
    fragment[TCP].sport = src_port
    fragment[TCP].dport = client_port
    fragment[TCP].seq = ack[TCP].seq + i * len(fragment[Raw])
    fragment[TCP].ack = ack[TCP].ack
    if(i < max_fr - 1):
        fragment[IP].flags = "MF"
    else:
        fragment[IP].flags = 0
    # send(fragment)
    # print(fragment.show())
    s.send(fragment)
    response = s.recv()
    print("response ",response)
    # Print a message indicating the sent fragment
    print(f"Sent fragment {i} of {len(server_fragments)}")
    # Wait for 0.1 seconds before sending the next fragment
    time.sleep(0.1)


# Initialize an empty list to store the data fragments from the client
data_frags = ""
i = 0
pkt = None
# Loop until a FIN packet is received from the client
while True:
    # Receive a packet from the client
    print("getting pkt")
    pkt = s.recv()
    print("got pkt")
    # Check if the packet is an IP fragment from the client and has a TCP layer
    # try:
    try:
        print("FLAG IS ",pkt[IP].flags)
    except: break
    if pkt[IP].src == client_ip and (pkt[IP].flags == "MF" or pkt[IP].flags==0):
        # Print a message indicating the received fragment
        print(f"Received fragment {i}")
        # Create an ACK packet for the fragment
        ack = IP(dst=client_ip)/TCP(sport=src_port, dport=client_port, flags="A", seq=pkt[TCP].ack, ack=pkt[TCP].seq + len(pkt[Raw]))
        # Send the ACK packet
        s.send(ack)
        # Append the fragment to the list for reassembly
        data_frags += bytes(pkt[Raw].load).decode()
        i +=1
    # except:
    if  (pkt[IP].flags == 0):
        # Print a message indicating the end of transmission
        print("End of transmission")
        # Break the loop
        break
    else:
        # s.sniff(f"tcp and dst host {src_port} and ", timeout = 5)
        continue

# Reassemble the data fragments into a single packet
# data = reassemble(data_frags)
print(data_frags)
print(len(data_frags))
client_ct = base64.b64decode(data_frags)
shared = frodo.kem_decaps(client_ct, sec)

# # Print the data payload
# print(data[Raw].load)

print("received key, sending final ack")
# Create an ACK packet for the FIN packet

# Send the FIN-ACK packet and receive the final ACK packet
print("sent")

print("shared",shared)
print("len ", len(shared))
pkt = s.recv()

print(pkt.summary())

key = shared + shared

ciphertext = pkt.getlayer(Raw)
cip = chacha20poly1305.ChaCha20Poly1305(key)
nonce = qrng
print("load is ",ciphertext.load)
plaintext = cip.decrypt(nonce, bytearray(ciphertext.load))
print(plaintext)

block_hash = "000004231a5ff53971c9a621522634a7c9bf617acae3dccaa4207a05c862abc3"
block_hash = zstd.compress(block_hash.encode(), 22)
block_hash = cip.encrypt(nonce, block_hash)
# Split the bytes into two halves
s1 = block_hash[:len(block_hash)//2]
s2 = block_hash[len(block_hash)//2:]



print("enc hash ",block_hash)
print("len of enc hash ",len(block_hash))
print("s1 ", s1)
print("s2 ", s2)

pkt = IP(dst=client_ip, options=IPOption(b""+s1))/TCP(sport=src_port, dport=client_port, flags="PA", ack=pkt.seq + 1, seq = pkt.ack,  options=[(255, b""+s2)]  )/Raw(load="plaintext")
print("sending ",plaintext)
fin_from_client = s.sr1(pkt)

print("waiting for fin")

print("got fin ", fin_from_client.show())
print("sending fin ack")
# Create the FIN ACK packet
fin = IP(dst=client_ip)/TCP(sport=src_port, dport=client_port, flags="PA", ack=fin_from_client.seq + 1, seq = fin_from_client.ack)
s.send(fin)
# CLose the connection
s.close()

print("shared secret is ",shared)

