## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
##
## This Protocol Layer was written by JRSmile <ffxiv_layer@behead.de>

# scapy.contrib.description = Final Fantasy 14 v5.58
# scapy.contrib.status = loads
# pylint: disable=invalid-name
"""
FFXVI (Final Fantasy 14 Packet Bundle 5.58).
"""


import urllib.request
import json
import struct

# from scapy.all import *
from scapy.layers.inet import TCP
from scapy.fields import (
    ByteField,
    LEShortField,
    LEIntField,
    IEEEFloatField,
    XLEShortField,
    LEShortEnumField,
    LEFieldLenField,
    XLEIntField,
    XShortField,
    PacketListField,
    LELongField,
    XByteField,
    ConditionalField,
)
from scapy.packet import Packet, bind_layers


# generate enum lists for FFXIV_IPC Types
with urllib.request.urlopen(
    "https://raw.githubusercontent.com/karashiiro/FFXIVOpcodes/master/opcodes.min.json"
) as url:
    opcodes = json.loads(url.read().decode())

    ServerZoneIpcType = {}
    for x in opcodes[0]["lists"][
        "ServerZoneIpcType"
    ]:  # 0 = Global client region, 1 = CN, 2 = KR
        ServerZoneIpcType[x["opcode"]] = x["name"]

    ServerLobbyIpcType = {}
    for x in opcodes[0]["lists"][
        "ServerLobbyIpcType"
    ]:  # 0 = Global client region, 1 = CN, 2 = KR
        ServerLobbyIpcType[x["opcode"]] = x["name"]

    ClientZoneIpcType = {}
    for x in opcodes[0]["lists"][
        "ClientZoneIpcType"
    ]:  # 0 = Global client region, 1 = CN, 2 = KR
        ClientZoneIpcType[x["opcode"]] = x["name"]

    ClientLobbyIpcType = {}
    for x in opcodes[0]["lists"][
        "ClientLobbyIpcType"
    ]:  # 0 = Global client region, 1 = CN, 2 = KR
        ClientLobbyIpcType[x["opcode"]] = x["name"]

    joined_list = (
        ServerZoneIpcType | ServerLobbyIpcType | ClientZoneIpcType | ClientLobbyIpcType
    )

# The Packet dissector class


class FFXIV_ActorMove(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "FFXIV_ActorMove"
    fields_desc = [
        ByteField("headRotation", None),
        ByteField("rotation", None),
        ByteField("animationType", None),
        ByteField("animationState", None),
        ByteField("animationSpeed", None),
        ByteField("unknownRotation", None),
        LEShortField("X", None),
        LEShortField("Y", None),
        LEShortField("Z", None),
        LEIntField("Unknown1", None),
    ]


class FFXIV_ActorCast(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "FFXIV_ActorCast"
    fields_desc = [
        LEShortField("Action", None),
        ByteField("SkillType", None),
        ByteField("Unknown1", None),
        LEIntField("ItemID", None),
        IEEEFloatField("CastTime", None),
        LEIntField("TargetID", None),
        IEEEFloatField("Rotation", None),
        LEIntField("Unknown2", None),
        LEShortField("posX", None),
        LEShortField("posY", None),
        LEShortField("posZ", None),
        LEShortField("Unknown3", None),
    ]


class FFXIV_ActorControl(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "FFXIV_ActorControl"
    fields_desc = [
        LEShortField("Type", None),
        LEShortField("Unknown1", None),
        LEIntField("Data0", None),
        LEIntField("Data1", None),
        LEIntField("Data2", None),
        LEIntField("Data3", None),
        LEIntField("Data4", None),
    ]


class FFXIV_UpdateHpMpTp(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "FFXIV_UpdateHpMpTp"
    fields_desc = [
        LEIntField("HP", None),
        LEShortField("MP", None),
        LEShortField("TP", None),
    ]


class FFXIV_UpdatePositionHandler(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "FFXIV_UpdatePositionHandler"
    fields_desc = [
        LEIntField("rot", None),
        LEIntField("2", None),
        LEIntField("x", None),
        LEIntField("z", None),
        LEIntField("y", None),
        LEIntField("6", None),
    ]


class FFXIV_IPC(Packet):
    """[IPC Opcode Multiplexer]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "FFXIV_IPC"
    fields_desc = [
        XLEShortField("ipc_magic", None),
        LEShortEnumField("ipc_type", None, joined_list),
        XLEShortField("ipc_unknown1", None),
        XLEShortField("ipc_server_id", None),
        LEIntField("ipc_epoch", None),
        XLEIntField("ipc_unknown2", None),
    ]


class FFXIV_ClientKeepAlive(Packet):
    """[recurring keepalive Packet]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "FFXIV_ClientKeepAlive"
    fields_desc = [LEIntField("ID", None), LEIntField("Epoch", None)]


class FFXIV_ServerKeepAlive(Packet):
    """[recurring keepalive Packet]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "FFXIV_ServerKeepAlive"
    fields_desc = [LEIntField("ID", None), LEIntField("Epoch", None)]


class FFXIV_Segment(Packet):
    """[segments the raw packet]

    Args:
        Packet ([Packet]): [raw packet stripped by FFXIV]
    """

    name = "FFXIV_Segment"
    fields_desc = [
        LEFieldLenField("Size", None, length_of="data", fmt="<I"),
        XLEIntField("Source", None),
        XLEIntField("Target", None),
        LEShortEnumField(
            "Type", None, {3: "IPC", 7: "ClientKeepAlive", 8: "ServerKeepAlive"}
        ),
        XShortField("Unknown", None),
        ConditionalField(
            PacketListField(
                "data",
                None,
                FFXIV_ServerKeepAlive,
                length_from=lambda pkt: pkt.Size - 16,
            ),
            lambda pkt: pkt.Type == 8,
        ),
        ConditionalField(
            PacketListField(
                "data",
                None,
                FFXIV_ClientKeepAlive,
                length_from=lambda pkt: pkt.Size - 16,
            ),
            lambda pkt: pkt.Type == 7,
        ),
        ConditionalField(
            PacketListField(
                "data", None, FFXIV_IPC, length_from=lambda pkt: pkt.Size - 16
            ),
            lambda pkt: pkt.Type == 3,
        ),
    ]

    def extract_padding(self, s):
        """[the key to multi segments in one bundle]

        Args:
            s ([Packet]): [the stripped packed from FFXIV Base Class]

        Returns:
            [Packet]: [Returns the packet but does not consumes the rest of the incomming packet.]
        """
        return "", s


class FFXIV(Packet):
    """[base Class]

    Args:
        Packet ([Packet]): [a raw packed strippt by the TCP Layer]

    Returns:
        [None]: [description]
    """

    name = "FFXIV"
    fields_desc = [
        XLEIntField("magic0", None),
        XLEIntField("magic1", None),
        XLEIntField("magic2", None),
        XLEIntField("magic3", None),
        LELongField("epoch", None),
        LEFieldLenField("bundle_len", None),
        XLEShortField("unknown1", None),
        XLEShortField("conn_type", None),
        LEFieldLenField("msg_count", None, count_of="data"),
        XByteField("encoding", None),
        ByteField("compressed", None),
        XLEShortField("unknown3", None),
        XLEShortField("unknown4", None),
        XLEShortField("unknown5", None),
        PacketListField(
            "data", None, FFXIV_Segment, count_from=lambda pkt: pkt.msg_count
        ),
    ]

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        """[called by sniff(session=TCPSession),
        reassembles the tcp stream if packet spans over multiple TCP packets]

        Args:
            data ([Packet]): [a raw packed strippt by the TCP Layer]
            metadata ([dict]): [stores partial streams]

        Returns:
            [Packet]: [reassembled Packet]
        """
        #pylint: disable=inconsistent-return-statements, unused-argument
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
bind_layers(FFXIV_IPC, FFXIV_ActorCast, ipc_type=349)
bind_layers(FFXIV_IPC, FFXIV_ActorControl, ipc_type=176)
