import urllib.request, json 
with urllib.request.urlopen("https://raw.githubusercontent.com/karashiiro/FFXIVOpcodes/master/opcodes.min.json") as url:
    opcodes = json.loads(url.read().decode())
    ServerZoneIpcType = {}
    for x in opcodes[0]["lists"]["ServerZoneIpcType"]:
        ServerZoneIpcType[x["opcode"]] = x["name"]
    
    print(ServerZoneIpcType)
    
    ServerLobbyIpcType = {}
    for x in opcodes[0]["lists"]["ServerLobbyIpcType"]:
        ServerLobbyIpcType[x["opcode"]] = x["name"]
    
    print(ServerLobbyIpcType)
    
    
        
    ClientZoneIpcType = {}
    for x in opcodes[0]["lists"]["ClientZoneIpcType"]:
        ClientZoneIpcType[x["opcode"]] = x["name"]
    
    print(ClientZoneIpcType)
    
    ClientLobbyIpcType = {}
    for x in opcodes[0]["lists"]["ClientLobbyIpcType"]:
        ClientLobbyIpcType[x["opcode"]] = x["name"]
    
    print(ClientLobbyIpcType)