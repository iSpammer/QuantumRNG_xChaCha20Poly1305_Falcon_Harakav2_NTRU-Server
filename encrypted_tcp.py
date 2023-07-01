import struct

from scapy import *
from scapy.fields import *
from scapy.packet import *
#
#
# def unpack(pkt):
#     pkt = bytes(pkt)
#     print("got bytes ",pkt)
#     tcp_header = bytes(pkt)  # TCP header is 20 bytes long (without options)
#     data_offset = (tcp_header[12] >> 4) * 4  # data offset is the first 4 bits of the byte at index 12
#     tcp_option = pkt[40:40 + data_offset - 20]  # TCP option is the rest of the header after index 20
#     data = pkt[40 + data_offset - 20:]  # data is the rest of the packet after the header
#     sport, dport, seq, ack, offset_reserved, flags, window, checksum, urgent = struct.unpack('!2s2sLLBBHHH', tcp_header)
#     offset = offset_reserved >> 4  # data offset is the first 4 bits of the byte
#     reserved = offset_reserved & 0xf  # reserved field is the last 4 bits of the byte
#
#     if tcp_option == b'\x02\x04\x05\xb4':  # check if the TCP option is maximum segment size with value 1460
#         data = data[4:]  # strip the first 4 bytes from the data payload
#
#     return data, sport, dport, seq, ack, flags
#
#
# class EncTCP:
#     def __init__(self, sport=b'\x00\x00', dport=b'\x00\x00', seq=0, ack=0, flags=0, reserved=0, tcpoption=b'\x00'):
#         self.sport = sport # source port as bytes
#         self.dport = dport # destination port as bytes
#         self.seq = seq # sequence number
#         self.ack = ack # acknowledgement number
#         self.flags = flags # flags
#         self.reserved = reserved # reserved field
#         self.tcpoption = tcpoption # tcp option field
#
#     def pack(self):
#         # pack the TCP header fields into a binary format
#         tcp_header = struct.pack('!2s2sLLBBHHH',
#             self.sport, # source port as bytes
#             self.dport, # destination port as bytes
#             self.seq, # sequence number
#             self.ack, # acknowledgement number
#             5 << 4 | self.reserved, # data offset (5 * 4 bytes) and reserved field
#             self.flags, # flags
#             65535, # window size
#             0, # checksum (0 for now)
#             0) # urgent pointer
#         return tcp_header + self.tcpoption

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

# Define a function to slice all the fields and return them as tuples of (name, value)
