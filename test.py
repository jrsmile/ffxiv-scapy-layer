#websocket stuff
import asyncio
from asyncio.windows_events import NULL
import websockets
import json
from importlib import reload
import parser_local as parser
import threading
import pyxivapi
import PySimpleGUI as sg
import vgamepad as vg
gamepad = vg.VDS4Gamepad()
gamepad.reset()
gamepad.update()

# Events https://pastebin.com/raw/D210QwNr

GameActive = False
zoneID = "1"
zoneName = "2"
posx = "3"
posy = "4"
posz = "5"
rot = "6"
AggroList = {}
TargetData = {}
log = ""

def onForceReload(message):
    print(f"{message}")
    return

def onGameExistsEvent(message):
    print(f"{message}")
    return

def onGameActiveChangedEvent(message):
    stud_obj = json.loads(message)
    global GameActive
    GameActive = stud_obj["detail"]["active"]
    return

def onLogEvent(message):
    stud_obj = json.loads(message)
    logs = stud_obj["detail"]["logs"]
    for logmessage in logs:
        try:
            reload(parser)
            short = parser.parse(logmessage)
            global log
            if short :
                #print(f"{short}")
                log += (f"{short}")
                log += "\n"
                
        except Exception as e:
            print(f"onLogEvent ERROR: {e}")
        
    return

def onImportLogEvent(message):
    print(f"{message}")
    return

def onInCombatChangedEvent(message):
    print(f"{message}")
    return

def onZoneChangedEvent(message):
    print(f"{message}")
    return

def onFateEvent(message):
    print(f"{message}")
    return

def onPlayerDied(message):
    print(f"{message}")
    return

def onPartyWipe(message):
    print(f"{message}")
    return

def onPlayerChangedEvent(message):
    stud_obj = json.loads(message)
    detail = stud_obj["detail"]
    global posx
    global posy
    global posz
    global rot
    posx = stud_obj["detail"]["pos"]["x"]
    posy = stud_obj["detail"]["pos"]["y"]
    posz = stud_obj["detail"]["pos"]["z"]
    rot  = stud_obj["detail"]["rotation"]
    #print(f"x: {posx} y: {posy} z: {posz} rot: {rot}")
    return

def onUserFileChanged(message):
    print(f"{message}")
    return

def EnmityTargetData(message):
    stud_obj = json.loads(message)
    global TargetData
    TargetData = stud_obj["Target"]
    return

def EnmityAggroList(message):
    stud_obj = json.loads(message)
    global AggroList
    AggroList = stud_obj["AggroList"]
    return

def InCombat(message):
    print(f"{message}")
    return

def CombatDataEvent(message):
    print(f"{message}")
    return

def FileChangedEvent(message):
    print(f"{message}")
    return

def LogLineEvent(message):
    print(f"{message}")
    return

def ImportedLogLinesEvent(message):
    print(f"{message}")
    return

def BroadcastMessageEvent(message):
    print(f"{message}")
    return

def ChangePrimaryPlayerEvent(message):
    print(f"{message}")
    return

def ChangeZoneEvent(message):
    print(f"{message}")
    return

def OnlineStatusChangedEvent(message):
    print(f"{message}")
    return

def PartyChangedEvent(message, websocket):
    print(f"Party Changed: {message} reqesting combatants")
    websocket.send("{\"call\":\"GetCombatants\"}")
    return

def ChangeZone(message):
    stud_obj = json.loads(message)
    global zoneID
    global zoneName
    zoneID = stud_obj["zoneID"]
    zoneName = stud_obj["zoneName"]
    return


events = {
    #cactbot
    "onForceReload": 	onForceReload,
    "onGameExistsEvent": 	onGameExistsEvent,
    "onGameActiveChangedEvent": 	onGameActiveChangedEvent,
    "onLogEvent": 	onLogEvent,
    "onImportLogEvent": 	onImportLogEvent,
    "onInCombatChangedEvent": 	onInCombatChangedEvent,
    "onZoneChangedEvent": 	onZoneChangedEvent,
    "onFateEvent": 	onFateEvent,
    "onPlayerDied": 	onPlayerDied,
    "onPartyWipe": 	onPartyWipe,
    "onPlayerChangedEvent": 	onPlayerChangedEvent,
    "onUserFileChanged": 	onUserFileChanged,
    #unknown
    "ChangeZone": ChangeZone,
    #enmity
    "EnmityTargetData": 	EnmityTargetData,
    "EnmityAggroList": 	EnmityAggroList,
    "InCombat": 	InCombat,
    #miniparse
    "CombatDataEvent": 	CombatDataEvent,
    "FileChangedEvent": 	FileChangedEvent,
    "LogLineEvent": 	LogLineEvent,
    "ImportedLogLinesEvent": 	ImportedLogLinesEvent,
    "BroadcastMessageEvent": 	BroadcastMessageEvent,
    "ChangePrimaryPlayerEvent": 	ChangePrimaryPlayerEvent,
    "ChangeZoneEvent": 	ChangeZoneEvent,
    "OnlineStatusChangedEvent": 	OnlineStatusChangedEvent,
    "PartyChangedEvent": 	PartyChangedEvent,
}

async def multiplexer(message,websocket):
    stud_obj = json.loads(message)
    msg_type = stud_obj["type"]
    global zoneID
    global zoneName
    global posx
    global posy
    global posz
    global rot
    global AggroList
    global TargetData
    if msg_type in events.keys():
        #print(msg_type + ": ", end="")
        if msg_type == "PartyChangedEvent":
            PartyChangedEvent(message,websocket)
        else:
            eval('' + msg_type + '(message)')

async def fetch_example_results():
    client = pyxivapi.XIVAPIClient(api_key="")

    recipe = await client.index_search(
        name="Vorsicht, Rutschgefahr!", 
        indexes=["Quest"], 
        columns=["Name_en"],
        language="de",
        string_algo="match"
    )

    await client.session.close()
    quest_name= recipe["Results"][0]["Name_en"].replace(' ','_')
    url = f"https://ffxiv.gamerescape.com/wiki/{quest_name}/NPCs"
    print(url)

async def client():
    uri = "ws://localhost:10501/ws"
    
    async with websockets.connect(uri) as websocket:
        name = "{\"call\":\"subscribe\",\"events\":["
        for event in events.keys():
            name = name + "\"" + event + "\","
            
        name = name[:-1] + "]}"

        await websocket.send(name)
        print(f"> {name}")
        
        loop = asyncio.get_event_loop()

        # Process messages received on the connection.
        async for message in websocket:
            await multiplexer(message, websocket)


def thread_function():
    sg.theme('DarkAmber')   # Add a touch of color
    layout = [[sg.Text(size=(120,1), font=('Calibri 13'), key='-TEXT-', background_color='black')],[sg.Text(size=(120,10), font=('Calibri 10'), key='-LOG-', background_color='black')]]
    window = sg.Window('Status', layout, no_titlebar=True, auto_size_buttons=False, keep_on_top=True, grab_anywhere=True, use_default_focus=False, return_keyboard_events=False, finalize=True,background_color='black',transparent_color='black', alpha_channel=.9,location=(500,0))
    global log
    old_output = ""
    while True:
        event, values = window.read(timeout=10)
        if event == sg.WIN_CLOSED:
            break
        
        output = f"Active: {GameActive} zoneID: {zoneID} zoneName: {zoneName} x: {posx} y: {posy} z: {posz} rot: {rot}"
        if output != old_output:
            window['-TEXT-'].update(output)
            old_output = output

        if len(log.split('\n')) >= 10:
            log = log.split("\n",1)[1]
            
        window['-LOG-'].update(f"Target: {TargetData} AggroList: {AggroList}")

if __name__ == "__main__":
    x = threading.Thread(target=thread_function)
    x.start()
    asyncio.get_event_loop().run_until_complete(client())