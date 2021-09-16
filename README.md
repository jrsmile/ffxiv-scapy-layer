# ffxiv-scapy-layer

Main File is ffxiv.py the layer that will end in scapys contrib folder.

OpCodes are beeing fetched during runtime from: https://raw.githubusercontent.com/karashiiro/FFXIVOpcodes/master/opcodes.min.json

sample capture file is pcap.py currently configured for europe.

other ranges can be found here: https://is.xivup.com/adv

## usage:
on windows make sure npcap is installed.
and python 3.9 or highter

pip install scapy

start scapy in the folder where ffxiv.px is present.

on the scapy command prompt enter the following:

import ffxiv

sniff(filter="tcp and net (195.82.50.0/24 or 204.2.229.0/24 or 124.150.157.0/24)", prn=lambda x:x.show(), store=0, session=TCPSession)

you shoud now be able to see the FF14 network traffic.