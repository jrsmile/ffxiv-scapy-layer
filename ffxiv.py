# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license
##
# This Protocol Layer was written by JRSmile <ffxiv_layer@behead.de>

# scapy.contrib.description = Final Fantasy 14 v5.58
# scapy.contrib.status = loads
# pylint: disable=invalid-name
"""
FFXVI (Final Fantasy 14 Packet Bundle 5.58).
"""

import zlib
import urllib.request
import json
import struct
from scapy.compat import base64_bytes, bytes_base64
from importlib import reload

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
    StrFixedLenField,
    FieldListField,
    IEEEDoubleField
)
from scapy.packet import Packet, bind_layers, raw
import scapy.packet

# generate enum lists for FFXIV_IPC Types
with urllib.request.urlopen(
    "https://cdn.jsdelivr.net/gh/karashiiro/FFXIVOpcodes@latest/opcodes.min.json"
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


class SystemLogMessage(Packet):
    """[SystemLogMessage]

    Args:
        Packet ([type]): [description]

    Returns:
        [type]: [description]
    """
    name = "SystemLogMessage"
    fields_desc = [
        #IEEEDoubleField("ContentID", None),
        #LEShortField("WorldID", None),
        #ByteField("flags", None),
        StrFixedLenField("MessageHeader", None, length=32),
        LEIntField("Unknown1", None),
        LEIntField("logmessageid", None),
        LEIntField("param1", None),
        LEIntField("param2", None),
        LEIntField("param3", None),
        LEIntField("padding1", None),
    ]
class Whisper(Packet):
    """[Whisper]

    Args:
        Packet ([type]): [description]
    """

    name = "Whisper"
    fields_desc = [
        #IEEEDoubleField("ContentID", None),
        #LEShortField("WorldID", None),
        #ByteField("flags", None),
        StrFixedLenField("Unknown", None, length=51),
        StrFixedLenField("Message", None, length=1024),
        StrFixedLenField("Unknown2", None, length=5),
    ]


class GroupMessage(Packet):
    """[GroupMessage]

    Args:
        Packet ([type]): [description]
    """

    name = "GroupMessage"
    fields_desc = [
        #IEEEDoubleField("ContentID", None),
        #LEShortField("WorldID", None),
        #ByteField("flags", None),
        StrFixedLenField("Username", None, length=8),
        StrFixedLenField("Message", None, length=1049),
    ]

class ChatHandler(Packet):
    """[ChatHandler]

    Args:
        Packet ([type]): [description]
    """

    name = "ChatHandler"
    fields_desc = [
        IEEEDoubleField("ContentID", None),
        LEShortField("WorldID", None),
        ByteField("flags", None),
        StrFixedLenField("Username", None, length=15),
        StrFixedLenField("Message", None, length=1030),
    ]


class InitZone(Packet):
    """[InitZone]

    Args:
        Packet ([type]): [description]
    """

    name = "InitZone"
    fields_desc = [
        LEShortField("server_id", None),
        LEShortField("zone_id", None),
        LEShortField("unknown1", None),
        LEShortField("content", None),
        LEIntField("unknown3", None),
        LEIntField("unknown4", None),
        ByteField("weather_id", None),
        ByteField("bitmask", None),
        ByteField("bitmask1", None),
        ByteField("unknown5", None),
        LEIntField("unknown8", None),
        LEShortField("festival_id", None),
        LEShortField("additional_festival_id", None),
        LEIntField("unknown9", None),
        LEIntField("unknown10", None),
        LEIntField("unknown11", None),
        LEIntField("unknown120", None),
        LEIntField("unknown121", None),
        LEIntField("unknown122", None),
        LEIntField("unknown123", None),
        LEIntField("unknown130", None),
        LEIntField("unknown131", None),
        LEIntField("unknown132", None),
        LEIntField("unknown140", None),
        LEIntField("unknown141", None),
        LEIntField("unknown142", None),
        LEIntField("unknown15", None)
    ]


class PlayerSpawn(Packet):
    """[PlayerSpawn]

    Args:
        Packet ([type]): [description]
    """

    name = "PlayerSpawn"
    fields_desc = [
        LEShortField("title", None),
        LEShortField("u1b", None),
        LEShortField("current_world_id", None),
        LEShortField("home_world_id", None),
        ByteField("gm_rank", None),
        ByteField("u3c", None),
        ByteField("u4", None),
        ByteField("online_status", None),
        ByteField("pose", None),
        ByteField("u5a", None),
        ByteField("u5b", None),
        ByteField("u5c", None),
        LELongField("target_id", None),
        LEIntField("u6", None),
        LEIntField("u7", None),
        LELongField("main_weapon_model", None),
        LELongField("sec_weapon_model", None),
        LELongField("craft_tool_model", None),
        LEIntField("u14", None),
        LEIntField("u15", None),
        LEIntField("b_npcbase", None),
        LEIntField("b_npcname", None),
        LEIntField("u18", None),
        LEIntField("u19", None),
        LEIntField("director_id", None),
        LEIntField("owner_id", None),
        LEIntField("u22", None),
        LEIntField("h_pmax", None),
        LEIntField("h_pcurr", None),
        LEIntField("display_flags", None),
        LEShortField("fate_id", None),
        LEShortField("m_pcurr", None),
        LEShortField("t_pcurr", None),
        LEShortField("m_pmax", None),
        LEShortField("t_pmax", None),
        LEShortField("model_chara", None),
        LEShortField("rotation", None),
        LEShortField("active_minion", None),
        ByteField("spawn_index", None),
        ByteField("state", None),
        ByteField("persistent_emote", None),
        ByteField("model_type", None),
        ByteField("subtype", None),
        ByteField("voice", None),
        ByteField("enemy_type", None),
        ByteField("level", None),
        ByteField("class_job", None),
        ByteField("u26d", None),
        LEShortField("u27a", None),
        ByteField("current_mount", None),
        ByteField("mount_head", None),
        ByteField("mount_body", None),
        ByteField("mount_feet", None),
        ByteField("mount_color", None),
        ByteField("scale", None),
        LEIntField("u29b", None),
        LEIntField("u30b", None),
        LEIntField("models0", None),
        LEIntField("models1", None),
        LEIntField("models2", None),
        LEIntField("models3", None),
        LEIntField("models4", None),
        LEIntField("models5", None),
        LEIntField("models6", None),
        LEIntField("models7", None),
        LEIntField("models8", None),
        LEIntField("models9", None),
        StrFixedLenField("nickname", None),
        StrFixedLenField("look", None),
        StrFixedLenField("fc_tag", None)
    ]


class ItemInfo(Packet):
    """[ItemInfo]

    Args:
        Packet ([type]): [description]
    """

    name = "ItemInfo"
    fields_desc = [
        LEIntField("index", None),
        LEIntField("unknown0", None),
        LEShortField("container_id", None),
        LEShortField("slot", None),
        LEIntField("quantity", None),
        LEIntField("catalog_id", None),
        LEIntField("reserved_flag", None),
        LELongField("signature_id", None),
        ByteField("quality", None),
        ByteField("attribute2", None),
        LEShortField("condition", None),
        LEShortField("spiritbond", None),
        LEShortField("stain", None),
        LEShortField("glamour_catalog_id", None),
        LEShortField("unknown6", None),
        LEShortField("materia1", None),
        LEShortField("materia2", None),
        LEShortField("materia3", None),
        LEShortField("materia4", None),
        LEShortField("materia5", None),
        ByteField("materia1_tier", None),
        ByteField("materia2_tier", None),
        ByteField("materia3_tier", None),
        ByteField("materia4_tier", None),
        ByteField("materia5_tier", None),
        ByteField("unknown10", None),
        LEIntField("unknown11", None)
    ]


class ContainerInfo(Packet):
    """[ContainerInfo]

    Args:
        Packet ([type]): [description]
    """

    name = "ContainerInfo"
    fields_desc = [
        LEIntField("Sequence", None),
        LEIntField("numItems", None),
        LEIntField("ContainerID", None),
        LEIntField("Unknown", None),
    ]


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
        IEEEDoubleField("TargetID", None),
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


class Unknown(Packet):
    """[all unknown opcodes]

    Args:
        Packet ([type]): [description]
    """

    name = "Unknown"
    fields_desc = [
        FieldListField("data", None, ByteField("", 0))
    ]


class OpcodeNotImplemented(Packet):
    """[all known opcodes that are not yet implemented]

    Args:
        Packet ([type]): [description]
    """

    name = "OpcodeNotImplemented"
    fields_desc = [
        FieldListField("data", None, ByteField("", 0))
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
        XLEIntField("ActorID", None),
        XLEIntField("LoginUserID", None),
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
    # pylint: disable=inconsistent-return-statements

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

    def mysummary(self):
        if self.haslayer(IPC):
            ipc_type = f"{self[IPC].ipc_type}"
            if self[IPC].ipc_type in joined_list.keys():
                return self.sprintf("FFXIV Bundle Length: %FFXIV.bundle_len% IPC Type: " + ipc_type + " " + joined_list[self[IPC].ipc_type])
            else:
                return self.sprintf("FFXIV Bundle Length: %FFXIV.bundle_len% IPC Type: " + ipc_type)
        else:
            return self.sprintf("FFXIV Bundle Length: %FFXIV.bundle_len%")

    def extract_padding(self, s):
        """[the key to multi segments in one bundle]

        Args:
            s ([Packet]): [the stripped packed from FFXIV Base Class]

        Returns:
            [Packet]: [Returns the packet but does not consumes the rest of the incomming packet.]
        """
        return "", s

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
        if struct.unpack("<I", data[:4])[0] == 1101025874 or (struct.unpack("<I", data[:4])[0] == 0 and struct.unpack("<I", data[4:8])[0] == 0 and struct.unpack("<I", data[8:12])[0] == 0 and struct.unpack("<I", data[12:16])[0] == 0):
            length = struct.unpack("<I", data[24:28])[0]  # get bundle_len
            fragment = FFXIV(data)
            if fragment.compressed:
                # data after header, was deflate compressed
                print("\n########### DECOMPRESSING ################")
                try:
                    data_len = len(data)
                    # without 40 bit ffxiv bundle header and 2 bit deflate header
                    inflated = zlib.decompress(
                        bytes_base64(data[40:]), -zlib.MAX_WBITS)
                    # rejoin data with inflated segments omitting the deflate header
                    data = b"".join([data[:42], inflated])
                    data_len2 = len(data)
                    print(
                        f"##########SUCCESS, inflated from {data_len} to {data_len2} #######")
                except Exception as e:
                    print(e)
                    print("########### FAILED #############\n")
                    return data  # void packet if inflate error

            if len(data) > length:  # got to much
                # return ffxiv bundle up to bundle_len
                pkt = data[:length]
                #print(                    f"### Got MORE actual len: {len(data)} proposed bundle_len: {length} ###")
                return FFXIV(pkt)
            elif len(data) < length:  # got less, not working
                #print(                    f"### Got LESS actual len: {len(data)} proposed bundle_len: {length} ###")
                return None  # push rest back to queue
            else:
                #print(                    f"### Got ENOU actual len: {len(data)} proposed bundle_len: {length} ###")
                return FFXIV(data)  # got exactly one bundle in one packet
        else:
            return data  # void packet if not an FFXIV bundle


bind_layers(TCP, FFXIV)
bind_layers(FFXIV, Segment)
bind_layers(Segment, IPC, Type=3)
bind_layers(Segment, ClientKeepAlive, Type=7)
bind_layers(Segment, ServerKeepAlive, Type=8)
bind_layers(IPC, GroupMessage, ipc_type=101)
bind_layers(IPC, Whisper, ipc_type=100)
bind_layers(IPC, SystemLogMessage, ipc_type=989)
# check for class existance and if implemented bind to IPC Layer
for k, v in joined_list.items():
    try:
        bind_layers(IPC, globals()[f"{v}"], ipc_type=k)
        #print(f"[+] Class {v} for Opcode {k} loaded...")
    except:
        #print(f"[-] Class {v} for Opcode {k} not implemented.")
        bind_layers(IPC, OpcodeNotImplemented, ipc_type=k)

for k in list(set(range(1, 1024)) - set(joined_list.keys())):
    bind_layers(IPC, Unknown, ipc_type=k)
