import logging
from collections import deque
from functools import partial
from time import sleep, time
from threading import Thread
from scapy.all import sniff, Packet, IPSession
import ffxiv

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


packets = deque()

def add_packet_to_queue(pkt: Packet):
    """ Operates on each sniffed packet
        Adds packet to the Queue for background processing
    """
    packets.append(pkt)


def poll_packet_queue(token: str):
    """  Background task to poll the Packets queue """
    while True:
        queue_size = len(packets)
        if queue_size > 0 and queue_size % 20 == 0:
            log.debug(f"Current queue size: {queue_size}")

        if queue_size == 0:
            # No packets, let's wait for some
            sleep(0.1)
            continue
        
        raw_packet = packets.popleft()
        try:
            raw_packet.show()
        except:
            log.exception(f"Failed to parse: {raw_packet.summary()}")
            continue


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)

    thread = Thread(target=partial(poll_packet_queue, token=""))
    thread.setDaemon(True)
    thread.start()
    log.info(f"Started queue polling")

    log.info(f"Sniffing packets... Ctrl + C to stop sniffing")
    sniff(filter="tcp and net 195.82.50.0/24", prn=add_packet_to_queue, store=0, session=IPSession) # 195.82.50.0/24 Europe