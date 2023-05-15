from scapy.all import *
from scapy.layers.inet import TCP, IP

# Define the server IP and port
server_ip = "192.168.68.139"
server_port = 4449


# Define a function to fragment a large message into smaller packets
def fragment_message(message, mtu=1500):
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
        packet = IP(dst=server_ip) / TCP(dport=server_port) / Raw(load=message[start:end])
        # Add the packet to the list of fragments
        fragments.append(packet)
    # Return the list of fragments
    return fragments


# Define a function to reassemble fragmented packets into a message
def reassemble_message(packets):
    # Sort the packets by sequence number
    packets.sort(key=lambda p: p[TCP].seq)
    # Initialize an empty message
    message = b""
    # Loop through each packet
    for p in packets:
        # Append the payload to the message
        message += p[Raw].load
    # Return the message
    return message


# Define a global variable to store the client IP and port
client_ip = None
client_port = None

# Define a global variable to store the server initial sequence number
server_isn = None

# Define a global variable to store the large message from the client
client_message = []

# Define a global variable to store the large message to the server
server_message = b"Hello, this is a large message from the server that will be fragmented into multiple packets."

# Define a global variable to store the fragments of the server message
server_fragments = fragment_message(server_message)


# Define a custom handler function that processes each packet received by sniff()
def handle_packet(pkt):
    # Use global variables inside the function
    global client_ip, client_port, server_isn, client_message, server_message, server_fragments
    synack = None

    # Check if the packet is an IP packet with TCP protocol and source or destination port is the server port
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and (pkt[TCP].sport == server_port or pkt[TCP].dport == server_port):

        # Check if the packet is a SYN packet from a client
        if pkt[TCP].flags == "S" and pkt[TCP].dport == server_port:
            # Get the client IP and port from the SYN packet
            client_ip = pkt[IP].src
            client_port = pkt[TCP].sport

            # Generate a random initial sequence number for the server
            server_isn = random.randint(0, 2 ** 32 - 1)

            # Send a SYN-ACK packet to the client
            synack = IP(dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=server_isn,
                                             ack=pkt[TCP].seq + 1)
            send(synack)

            # Print a message indicating that TCP handshake is started
            print("TCP handshake started")

        # Check if the packet is an ACK packet from the client that matches the SYN-ACK packet sent by the server
        elif pkt[TCP].flags == "A" and pkt[TCP].sport == client_port and pkt[TCP].seq == synack[TCP].ack and pkt[
            TCP].ack == synack[TCP].seq + 1:
            # Print a message indicating that TCP handshake is completed
            print("TCP handshake completed")

        # Check if the packet is a PSH-ACK packet from the client that contains part of the large message
        elif pkt[TCP].flags == "PA" and pkt[TCP].sport == client_port and pkt[TCP].ack == synack[TCP].seq + 1 and len(
                pkt[Raw]) > 0:
            # Append the packet to the list of packets that form the client message
            client_message.append(pkt)

            # Send an ACK packet to the client to acknowledge the received fragment
            ack = IP(dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=pkt[TCP].ack,
                                          ack=pkt[TCP].seq + len(pkt[Raw]))
            send(ack)

            # Check if the packet is the last fragment of the client message
            if pkt[TCP].seq + len(pkt[Raw]) == client_message[-1][TCP].seq + len(client_message[-1][Raw]):
                # Reassemble the client message from the packets
                message = reassemble_message(client_message)

                # Print the message received from the client
                print(f"Message received from client: {message}")

                # Send each fragment of the server message to the client with increasing sequence numbers
                for i, fragment in enumerate(server_fragments):
                    fragment[TCP].sport = server_port
                    fragment[TCP].dport = client_port
                    fragment[TCP].seq = ack[TCP].seq + i * len(fragment[Raw])
                    fragment[TCP].ack = ack[TCP].ack
                    send(fragment)

                # Print the message sent to the client
                print(f"Message sent to client: {server_message}")

                # Send a FIN packet to the client to terminate the connection
                fin = IP(dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="FA",
                                              seq=server_fragments[-1][TCP].seq + len(server_fragments[-1][Raw]),
                                              ack=ack[TCP].ack)
                send(fin)

                # Print a message indicating that TCP connection is closed
                print("TCP connection closed")

# Call the sniff function with the custom handler function
sniff(prn=handle_packet, filter=f"ip and tcp and port {server_port}")
