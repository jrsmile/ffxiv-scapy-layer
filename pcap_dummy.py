import json
import urllib.request
import logging
import os.path
from collections import deque
from functools import partial
from time import sleep, time
from threading import Thread
from scapy.all import sniff, Packet, TCPSession, conf, load_layer
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *
from scapy.utils import wrpcap
from ffxiv import IPC, FFXIV, ChatHandler, UpdatePositionHandler, Segment, ServerKeepAlive, ClientKeepAlive

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


# conf.layers.filter([Ether, IP, TCP, FFXIV]) # böse, ganz böse

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


packets = deque()


def add_packet_to_queue(pkt: Packet):
    """Operates on each sniffed packet
    Adds packet to the Queue for background processing
    """
    packets.append(pkt)


def poll_packet_queue(token: str):
    """Background task to poll the Packets queue"""
    while True:
        queue_size = len(packets)
        if queue_size > 0 and queue_size % 20 == 0:
            log.debug(f"Current queue size: {queue_size}")

        if queue_size == 0:
            # No packets, let's wait for some
            sleep(0.01)
            continue

        raw_packet = packets.popleft()
        try:
            print(f"{raw_packet.summary()}")
            '''
            if raw_packet.haslayer(IPC) and (raw_packet[IPC].ipc_magic == 0x14):
                # other magic types are possibly TLS encrypted
                if raw_packet[IPC].ipc_type in joined_list.keys():
                    pdfpath = f"PDFs/IPC_{raw_packet[IPC].ipc_type}_{joined_list[raw_packet[IPC].ipc_type]}.pdf"
                else:
                    pdfpath = f"PDFs/IPC_{raw_packet[IPC].ipc_type}.pdf"
                if not os.path.isfile(pdfpath):
                    raw_packet[IPC].pdfdump(pdfpath)
                    wrpcap('IPCs.pcap', raw_packet, append=True)
            '''
            # if raw_packet.haslayer(TLS):
            #    raw_packet.show()
            # if raw_packet.haslayer(FFXIV_UpdatePositionHandler): # and raw_packet[FFXIV].msg_count > 1:
            #    posX = raw_packet["FFXIV_UpdatePositionHandler"].x
            #    posY = raw_packet["FFXIV_UpdatePositionHandler"].y
            #    posZ = raw_packet["FFXIV_UpdatePositionHandler"].z
            #    print(f"X: {posX} Y: {posY} Z: {posZ}")

            # if raw_packet.haslayer(IPC) and not raw_packet.haslayer(Raw):
            #    result = f"{raw_packet.show(dump=True)}"
            #    for item in result.split("\n"):
            #        if "ipc_type" in item:
            #            print(item.strip())

            #        if "Message" in item:
            #            print(item.strip())

            # if not raw_packet.haslayer(FFXIV):
            #    if not raw_packet[TCP].flags == "A":
            #        print(f"{raw_packet.summary()}")

            if raw_packet.haslayer(FFXIV) and raw_packet[FFXIV].compressed:
                #    print(
                #        "###############################################################################")
                raw_packet.show()

        except:
            log.exception(f"Failed to parse: {raw_packet.summary()}")
            continue


if __name__ == "__main__":
    logger = logging.getLogger("scapy")
    logger.setLevel(logging.INFO)

    thread = Thread(target=partial(poll_packet_queue, token=""))
    thread.setDaemon(True)
    thread.start()
    log.info(f"Started queue polling")

    log.info(f"Sniffing packets... Ctrl + C to stop sniffing")
    sniff(
        offline="sample.pcap",
        #filter="(tcp or udp) and net (195.82.50.0/24 or 204.2.229.0/24 or 124.150.157.0/24)",
        prn=add_packet_to_queue,
        store=0,
        session=TCPSession,
    )
    # 195.82.50.0/24 Europe
    # 204.2.229.0/24 NA
    # 124.150.157.0/24 Japan
