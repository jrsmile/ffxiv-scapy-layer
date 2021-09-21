import pytest
from scapy.all import *
from ffxiv import *

# Arrange


@pytest.fixture
def test_traffic():
    packets = rdpcap('IPCs.pcap')
    return packets


def test_no_raw(test_traffic):
    # Act
    for packet in test_traffic:
        packet.show()
        # Assert
        assert not packet.haslayer("raw")


@pytest.mark.xfail(reason="not done yet")
def test_all_opcodes_implemented(test_traffic):
    # Act
    for packet in test_traffic:
        packet.show()
        # Assert
        assert not packet.haslayer("OpcodeNotImplemented")


@pytest.mark.xfail(reason="many OPCodes unknown")
def test_all_opcodes_known(test_traffic):
    # Act
    for packet in test_traffic:
        packet.show()
        # Assert
        assert not packet.haslayer("Unknown")
