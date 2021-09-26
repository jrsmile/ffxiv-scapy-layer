import zlib
from scapy.compat import bytes_base64
from scapy.packet import raw


def deflate(fragment, len):
    #zPay = fragment.payload
    #fragment.remove_payload
    # 789cb3606060d8bda34460ae87870033902dc2b0014832332c5fe39f086430e830daace006d2ef81f81b03022c6044d75782a28f575494410da80684b7002183cae5b748da1f8c30365d81703d0303002bbf2584
    # s2BgYNi9o0RgroeHADOQLcKwAUgyMyxf458IZDDoMNqs4AbS74H4GwMCLGBE11eCoo9XVJRBDagGhLcAIYPK5bdI2h+MMDZdgXA9AwMAK78lhA==
    #print(raw(fragment)[40:].hex())  # with zlib header
    b64 = bytes_base64(raw(fragment)[42:])  # without header in base64
    print(f"COMPRESSED bundle_len: {len} {b64}")
    inflated = zlib.decompress(b64, -15)
    #print(inflated)
    restored_fragment = fragment[:42] + inflated
    return restored_fragment
