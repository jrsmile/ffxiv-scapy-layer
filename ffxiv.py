## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
##
## This Protocol Layer was written by JRSmile <ffxiv_layer@behead.de>

# scapy.contrib.description = Final Fantasy 14 v5.58
# scapy.contrib.status = loads

"""
FFXVI (Final Fantasy 14 Packet Bundle 5.58).
"""


from scapy.all import *
from scapy.all import Ether, IP, TCP
import json
import urllib.request, json 

# generate enum lists for FFXIV_IPC Types
with urllib.request.urlopen("https://raw.githubusercontent.com/karashiiro/FFXIVOpcodes/master/opcodes.min.json") as url:
    opcodes = json.loads(url.read().decode())

    ServerZoneIpcType = {}
    for x in opcodes[0]["lists"]["ServerZoneIpcType"]: # 0 = Global client region, 1 = CN, 2 = KR
        ServerZoneIpcType[x["opcode"]] = x["name"]
    
    
    ServerLobbyIpcType = {}
    for x in opcodes[0]["lists"]["ServerLobbyIpcType"]: # 0 = Global client region, 1 = CN, 2 = KR
        ServerLobbyIpcType[x["opcode"]] = x["name"]
    
        
    ClientZoneIpcType = {}
    for x in opcodes[0]["lists"]["ClientZoneIpcType"]: # 0 = Global client region, 1 = CN, 2 = KR
        ClientZoneIpcType[x["opcode"]] = x["name"]
    
    
    ClientLobbyIpcType = {}
    for x in opcodes[0]["lists"]["ClientLobbyIpcType"]: # 0 = Global client region, 1 = CN, 2 = KR
        ClientLobbyIpcType[x["opcode"]] = x["name"]
    
    joined_list = ServerZoneIpcType | ServerLobbyIpcType | ClientZoneIpcType | ClientLobbyIpcType
    print(joined_list)
    
# The Packet dissector class

class FFXIV_UpdateHpMpTp(Packet):
    name = "FFXIV_UpdateHpMpTp"
    fields_desc=[LEIntField("HP",               None),
                 LEShortField("MP",             None),
                 LEShortField("TP",             None),
                 ]


class FFXIV_UpdatePositionHandler(Packet):
    name = "FFXIV_UpdatePositionHandler"
    fields_desc=[LEIntField("rot",              None),
                 LEIntField("2",                None),
                 LEIntField("x",                None),
                 LEIntField("y",                None),
                 LEIntField("z",                None),
                 LEIntField("6",                None),
                 LEIntField("7",                None),
                 LEIntField("8",                None),
                 LEIntField("9",                None),
                 LEIntField("10",               None),
                 ]

class FFXIV_IPC(Packet):
    name = "FFXIV_IPC"
    fields_desc=[XLEShortField("ipc_magic",         None),
                 #MultipleTypeField([(LEShortEnumField("ipc_type", None, ServerZoneIpcType),  lambda pkt: pkt.underlayer.payload in ServerZoneIpcType.keys()),
                 #                   (LEShortEnumField("ipc_type", None, ServerLobbyIpcType), lambda pkt: pkt.underlayer.payload in ServerLobbyIpcType.keys()),
                 #                   (LEShortEnumField("ipc_type", None, ClientZoneIpcType),  lambda pkt: pkt.underlayer.payload in ClientZoneIpcType.keys()),
                 #                   (LEShortEnumField("ipc_type", None, ClientLobbyIpcType), lambda pkt: pkt.underlayer.payload in ClientLobbyIpcType.keys()),
                 #                   ],   LEShortField("ipc_type", None)),
                 LEShortEnumField("ipc_type", None, joined_list),
                 XLEShortField("ipc_unknown1",      None),
                 XLEShortField("ipc_server_id",     None),
                 LEIntField("ipc_epoch",            None),
                 XLEIntField("ipc_unknown2",        None),
                 PacketListField("data",            None, FFXIV_UpdatePositionHandler, length_from = lambda pkt: pkt.underlayer.Size -16)
                 ]

class FFXIV_ClientKeepAlive(Packet):
    name = "FFXIV_ClientKeepAlive"
    fields_desc=[LEIntField("ID",                   None),
                 LEIntField("Epoch",                None)
                 ]

class FFXIV_ServerKeepAlive(Packet):
    name = "FFXIV_ServerKeepAlive"
    fields_desc=[LEIntField("ID",                   None),
                 LEIntField("Epoch",                None)
                 ]

class FFXIV_Segment(Packet):
    name = "FFXIV_Segment"
    fields_desc=[ LEFieldLenField("Size",    None, length_of="data",fmt="<I"), 
                  XLEIntField("Source",      None), 
                  XLEIntField("Target",      None), 
                  LEShortEnumField("Type",   None, {3:"IPC",7:"ClientKeepAlive",8:"ServerKeepAlive"}), 
                  XShortField("Unknown",     None),
                  ConditionalField(PacketListField("data",    None, FFXIV_ServerKeepAlive, length_from = lambda pkt: pkt.Size) , lambda pkt: pkt.Type == 8),
                  ConditionalField(PacketListField("data",    None, FFXIV_ClientKeepAlive, length_from = lambda pkt: pkt.Size) , lambda pkt: pkt.Type == 7),
                  ConditionalField(PacketListField("data",    None, FFXIV_IPC, length_from = lambda pkt: pkt.Size)             , lambda pkt: pkt.Type == 3)
                 ]

class FFXIV(Packet):
    name = "FFXIV"
    fields_desc=[ XLEIntField("magic0",       None),
                  XLEIntField("magic1",       None),
                  XLEIntField("magic2",       None),
                  XLEIntField("magic3",       None),
                  LELongField("epoch",        None),
                  LEShortField("bundle_len",  None),
                  XLEShortField("unknown1",   None),
                  XLEShortField("conn_type",  None),
                  LEFieldLenField("msg_count",None, count_of="data"),
                  XByteField("encoding",      None),
                  ByteField("compressed",     None),
                  XLEShortField("unknown3" ,  None),
                  XLEShortField("unknown4" ,  None),
                  XLEShortField("unknown5" ,  None),
                  PacketListField("data",     None, FFXIV_Segment, count_from = lambda pkt: pkt.msg_count)
                 ]
    
    @classmethod
    def tcp_reassemble(cls, data, metadata):
        length = struct.unpack("<I", data[24:28])[0]
        if len(data) == length:
            return FFXIV(data)

bind_layers(TCP, FFXIV, sport=54993)
bind_layers(TCP, FFXIV, dport=54993)
bind_layers(TCP, FFXIV, sport=54993, dport=54993)
bind_layers(TCP, FFXIV, sport=54994)
bind_layers(TCP, FFXIV, dport=54994)
bind_layers(TCP, FFXIV, sport=54994, dport=54994)
bind_layers(FFXIV, FFXIV_Segment)
bind_layers(FFXIV_Segment, FFXIV_IPC, Type=3)
bind_layers(FFXIV_Segment, FFXIV_ClientKeepAlive, Type=7)
bind_layers(FFXIV_Segment, FFXIV_ServerKeepAlive, Type=8)
bind_layers(FFXIV_IPC, FFXIV_UpdatePositionHandler, ipc_type=431)
bind_layers(FFXIV_IPC, FFXIV_UpdateHpMpTp, ipc_type=423)

"""
Selftests
"""

if __name__ == "__main__":
    print("\n[+] Starting Selftest")
    from scapy.utils import PcapWriter
    import os
    
    try:
        os.remove("net2.pcap")
    except:
        print("") 

    print('[+] Writing net.pcap file...')
    cap = PcapWriter("net2.pcap", append=True, sync=True)
    for i in range(1):
        packet = Ether(src="dc:15:c8:2c:eb:90",dst="04:d4:c4:4b:2d:6f")/IP(src="195.82.50.55",dst="192.168.178.22")/TCP(sport=54993,dport=53985)/FFXIV(
            magic0=0x41a05252,
            magic1=0xe2465dff,
            magic2=0x4d642a7f,
            magic3=0x75c4997b,
            epoch=1631186260371,
            bundle_len=104,
            unknown1=0x0000,
            conn_type=0x0000,
            msg_count=1,
            encoding=0x01,
            compressed=0,
            unknown3=0x0000,
            unknown4=0x0000,
            unknown5=0x0000,
            )/FFXIV_Segment(
                #Size=64,
                Source=0x1073851f,
                Target=0x1073851f,
                Type="ServerKeepAlive",
                Unknown=0x00000000,
                )/FFXIV_ServerKeepAlive(ID=276006175, Epoch=1631269719)
        cap.write(packet)

    print ('[+] Examining net.pcap file...\n')
    packets = sniff(offline='walking.pcap')#, session=TCPSession)
    for p in packets: 
        hexdump(p)
        p.show()