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


class InventoryActionAck(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "InventoryActionAck"
    fields_desc = [
        LEIntField("Sequence", None),
        LEIntField("Type", None),
        LEIntField("Unknown1", None),
        LEIntField("Unknown2", None),
    ]


class UpdateInventorySlot(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]

    Returns:
        [type]: [description]
    """
    name = "UpdateInventorySlot"
    fields_desc = [
        LEIntField("Index", None),
        LEIntField("Unknown0", None),
        LEShortField("ContainerId", None),
        LEShortField("Slot", None),
        LEIntField("Quantity", None),
        LEIntField("CatalogId", None),
        LEIntField("ReservedFlag", None),
        IEEEFloatField("SignatureId", None),
        ByteField("Quality", None),
        ByteField("Attribute2", None),
        LEShortField("Condition", None),
        LEShortField("Spiritbond", None),
        LEShortField("Stain", None),
        LEShortField("GlamourCatalogId", None),
        LEShortField("Unknown6", None),
        LEShortField("Materia1", None),
        LEShortField("Materia2", None),
        LEShortField("Materia3", None),
        LEShortField("Materia4", None),
        LEShortField("Materia5", None),
        ByteField("Materia1Tier", None),
        ByteField("Materia2Tier", None),
        ByteField("Materia3Tier", None),
        ByteField("Materia4Tier", None),
        ByteField("Materia5Tier", None),
        ByteField("Unknown10", None),
        LEIntField("Unknown11", None)
    ]
class ClientTrigger(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]

    Returns:
        [type]: [description]
    """
    name = "ClientTrigger"
    fields_desc = [
        XLEShortField("commandID", None),
        ByteField("unknown20", None),
        ByteField("unknown21", None),
        LEIntField("param11", None),
        LEIntField("param12", None),
        LEIntField("param2", None),
        LEIntField("param4", None),
        LEIntField("param5", None),
        LELongField("param3", None)
    ]


class UpdatePositionInstance(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "UpdatePositionInstance"
    fields_desc = [
        LEIntField("rot", None),
        LEIntField("2", None),
        LEIntField("x", None),
        LEIntField("z", None),
        LEIntField("y", None),
        LEIntField("6", None),
        LEIntField("7", None),
        LEIntField("8", None),
        LEIntField("9", None),
        LEIntField("10", None)
    ]


class ActorSetPos(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorSetPos"
    fields_desc = [
        LEShortField("r16", None),
        ByteField("waitForLoad", None),
        ByteField("Unknown1", None),
        LEIntField("Unknown2", None),
        IEEEFloatField("x", None),
        IEEEFloatField("y", None),
        IEEEFloatField("z", None),
        LEIntField("Unknown3", None),
    ]
class ActorMove(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorMove"
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


class ActorGauge(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorGauge"
    fields_desc = [
        ByteField("classJobID", None),
        ByteField("data0", None),
        ByteField("data1", None),
        ByteField("data2", None),
        ByteField("data3", None),
        ByteField("data4", None),
        ByteField("data5", None),
        ByteField("data6", None),
        ByteField("data7", None),
        ByteField("data8", None),
        ByteField("data9", None),
        ByteField("data10", None),
        ByteField("data11", None),
        ByteField("data12", None),
        ByteField("data13", None),
        ByteField("data14", None)
    ]

class ActorCast(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorCast"
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
        LEShortField("Unknown3", None)
    ]


class ActorControlTarget(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorControlTarget"
    fields_desc = [
        LEShortField("Category", None),
        LEShortField("padding", None),
        LEIntField("param1", None),
        LEIntField("param2", None),
        LEIntField("param3", None),
        LEIntField("param4", None),
        LEIntField("padding1", None),
        IEEEFloatField("TargetID", None)
    ]


class ActorControlSelf(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorControlSelf"
    fields_desc = [
        LEShortField("Type", None),
        LEShortField("Unknown0", None),
        LEIntField("Data0", None),
        LEIntField("Data1", None),
        LEIntField("Data2", None),
        LEIntField("Data3", None),
        LEIntField("Data4", None),
        LEIntField("Data5", None),
        LEIntField("Data6", None)
    ]

class ActorControl(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "ActorControl"
    fields_desc = [
        LEShortField("Type", None),
        LEShortField("Unknown1", None),
        LEIntField("Data0", None),
        LEIntField("Data1", None),
        LEIntField("Data2", None),
        LEIntField("Data3", None),
        LEIntField("Data4", None)
    ]


class UpdateHpMpTp(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "UpdateHpMpTp"
    fields_desc = [
        LEIntField("HP", None),
        LEShortField("MP", None),
        LEShortField("TP", None)
    ]


class UpdatePositionHandler(Packet):
    """[summary]

    Args:
        Packet ([type]): [description]
    """

    name = "UpdatePositionHandler"
    fields_desc = [
        LEIntField("rot", None),
        LEIntField("2", None),
        LEIntField("x", None),
        LEIntField("z", None),
        LEIntField("y", None),
        LEIntField("6", None),
        LEIntField("7", None),
        LEIntField("8", None),
        LEIntField("9", None),
        LEIntField("10", None)
    ]


class IPC(Packet):
    """[IPC Opcode Multiplexer]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "IPC"
    fields_desc = [
        XLEShortField("ipc_magic", None),
        LEShortEnumField("ipc_type", None, joined_list),
        XLEShortField("ipc_unknown1", None),
        XLEShortField("ipc_server_id", None),
        LEIntField("ipc_epoch", None),
        XLEIntField("ipc_unknown2", None)
    ]


class ClientKeepAlive(Packet):
    """[recurring keepalive Packet]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "ClientKeepAlive"
    fields_desc = [LEIntField("ID", None), LEIntField("Epoch", None)]


class ServerKeepAlive(Packet):
    """[recurring keepalive Packet]

    Args:
        Packet ([Packet]): [raw Packet stripped by FFXIV_Segment]
    """

    name = "ServerKeepAlive"
    fields_desc = [LEIntField("ID", None), LEIntField("Epoch", None)]


class Segment(Packet):
    """[segments the raw packet]

    Args:
        Packet ([Packet]): [raw packet stripped by FFXIV]
    """

    name = "Segment"
    fields_desc = [
        LEFieldLenField("Size", None, length_of="data", fmt="<I"),
        XLEIntField("Source", None),
        XLEIntField("Target", None),
        LEShortEnumField(
            "Type", None, {3: "IPC", 7: "ClientKeepAlive",
                           8: "ServerKeepAlive"}
        ),
        XShortField("Unknown", None),
        ConditionalField(
            PacketListField(
                "data",
                None,
                ServerKeepAlive,
                length_from=lambda pkt: pkt.Size - 16,
            ),
            lambda pkt: pkt.Type == 8,
        ),
        ConditionalField(
            PacketListField(
                "data",
                None,
                ClientKeepAlive,
                length_from=lambda pkt: pkt.Size - 16,
            ),
            lambda pkt: pkt.Type == 7,
        ),
        ConditionalField(
            PacketListField(
                "data", None, IPC, length_from=lambda pkt: pkt.Size - 16
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
    #pylint: disable=inconsistent-return-statements

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
        PacketListField("data", None, Segment,
                        count_from=lambda pkt: pkt.msg_count),
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
        #pylint: disable=unused-argument

        length = struct.unpack("<I", data[24:28])[0]
        if len(data) == length:
            return FFXIV(data)


bind_layers(TCP, FFXIV, sport=54993)
bind_layers(TCP, FFXIV, dport=54993)
bind_layers(TCP, FFXIV, sport=54993, dport=54993)
bind_layers(TCP, FFXIV, sport=54994)
bind_layers(TCP, FFXIV, dport=54994)
bind_layers(TCP, FFXIV, sport=54994, dport=54994)
bind_layers(FFXIV, Segment)
bind_layers(Segment, IPC, Type=3)
bind_layers(Segment, ClientKeepAlive, Type=7)
bind_layers(Segment, ServerKeepAlive, Type=8)

# check for class existance and if implemented bind to IPC Layer
for k, v in joined_list.items():
    try:
        eval(f"bind_layers(IPC, {v}, ipc_type={k})")
        print(f"[+] Class {v} for Opcode {k} loaded...")
    except:
        print(f"[-] Class {v} for Opcode {k} not implemented.")
