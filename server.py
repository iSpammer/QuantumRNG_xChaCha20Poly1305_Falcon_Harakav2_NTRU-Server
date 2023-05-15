# Import scapy library
from scapy.all import *
from scapy.layers.inet import *
import codecs

from scapy.layers.inet import _IPOption_HDR

import frodokem

# Define IP and port of the server
server_ip = "192.168.68.139"
server_port = 4449

frodo = frodokem.FrodoKEM640()
# Define a function to handle each connection
def handle_connection(pkt):
    # Check if it is a TCP packet with SYN flag set
    if pkt[TCP].flags == "S":
        # Get the source IP and port of the client
        client_ip = pkt[IP].src
        client_port = pkt[TCP].sport
        # Create a SYN/ACK packet with the initial sequence number and acknowledgement number
        syn_ack = IP(dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=200, ack=pkt.seq + 1)

        # Send the SYN/ACK packet to the client
        send(syn_ack)

        # Receive an ACK packet from the client
        ack = sniff(filter=f"tcp and src host {client_ip} and src port {client_port} and dst host {server_ip} and dst port {server_port}", count=1)[0]

        # Check if it is a TCP packet with ACK flag set
        if ack[TCP].flags == "A":
            # Receive a PSH/ACK packet with data from the client
            psh_ack = sniff(filter=f"tcp and src host {client_ip} and src port {client_port} and dst host {server_ip} and dst port {server_port}", count=1)[0]
            # Initialize an empty buffer for the received data
            data_buffer = b""
            # Check if it is a TCP packet with PSH and ACK flags set and has data
            # if psh_ack[TCP].flags == "PA" and Raw in psh_ack:
            if Raw in psh_ack:
                # Print the data from the client
                client_pk = (psh_ack[Raw].load.decode("utf-8", "ignore"))

                print("decodd")
                print(len(client_pk))
                print("yarab")
                print(len(psh_ack[Raw].load))
                msg = "Hello client"
                res = 0
                if(psh_ack[TCP].reserved == 5):
                    bob_ciphertext, bob_shared_secret = frodo.encaps((psh_ack[Raw].load))
                    msg = bob_ciphertext
                    res = 4
                    print(bob_shared_secret)

                # Create a PSH/ACK packet with data "Hello client"
                psh_ack_reply = IP(dst=client_ip)/TCP(sport=server_port, dport=client_port, reserved = res, flags="PA", seq=psh_ack.ack, ack=psh_ack.seq + len(psh_ack[Raw].load))/Raw(load=msg)

                # Send the PSH/ACK packet to the client
                send(psh_ack_reply)

                # Receive an ACK packet from the client
                ack2 = sniff(filter=f"tcp and src host {client_ip} and src port {client_port} and dst host {server_ip} and dst port {server_port}", count=1)[0]

                # Check if it is a TCP packet with ACK flag set
                if ack2[TCP].flags == "A":
                    # Receive a FIN/ACK packet from the client
                    fin_ack = sniff(filter=f"tcp and src host {client_ip} and src port {client_port} and dst host {server_ip} and dst port {server_port}", count=1)[0]

                    # Check if it is a TCP packet with FIN and ACK flags set
                    if fin_ack[TCP].flags == "FA":
                        # Create an ACK packet to acknowledge the FIN from the client
                        ack3 = IP(dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="A", seq=fin_ack.ack, ack=fin_ack.seq + 1)

                        # Send the ACK packet to the client
                        send(ack3)

                        # Create a FIN/ACK packet to terminate the connection
                        fin_ack_reply = IP(dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="FA", seq=ack3.seq, ack=ack3.ack)

                        # Send the FIN/ACK packet to the client
                        send(fin_ack_reply)

                        # Receive an ACK packet from the client
                        ack4 = sniff(filter=f"tcp and src host {client_ip} and src port {client_port} and dst host {server_ip} and dst port {server_port}", count=1)[0]

                        # Check if it is a TCP packet with ACK flag set
                        if ack4[TCP].flags == "A":
                            # Close the connection and return from the function
                            print("Connection closed")
                            return

# Sniff for incoming TCP packets on the server port and call the handle_connection function for each one
sniff(filter=f"tcp and dst host {server_ip} and dst port {server_port}", prn=handle_connection)


