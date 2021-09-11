def parse(logs):
    #logs = logs.replace(":"," ")
        #LogLine,
        #ChangeZone,
        #ChangePrimaryPlayer,
        #AddCombatant,
        #RemoveCombatant,
        #AddBuff,
        #RemoveBuff,
        #FlyingText,
        #OutgoingAbility,
        #IncomingAbility = 10,
        #PartyList,
        #PlayerStats,
        #CombatantHP,
        #ParsedPartyMember,
        #NetworkStartsCasting = 20,
        #NetworkAbility,
        #NetworkAOEAbility,
        #NetworkCancelAbility,
        #NetworkDoT,
        #NetworkDeath,
        #NetworkBuff,
        #NetworkTargetIcon,
        #NetworkTargetMarker = 29,
        #NetworkBuffRemove,
        #NetworkGauge,
        #NetworkWorld,
        #Network6D,
        #NetworkNameToggle,
        #NetworkTether,
        #NetworkLimitBreak,
        #NetworkEffectResult,
        #NetworkStatusList,
        #NetworkUpdateHp,
        #Settings = 249,
        #Process,
        #Debug,
        #PacketDump,
        #Version,
        #Error,
        #Timer
    
    timestamp = logs[:14]
    command = logs[15:].split(":")
    if command[0] == "00":
        if command[1] == "000a":
            return f"Spieler: {command[2]} sagt: {command[3]}"
        if command[1] == "000b":
            return f"Spieler: {command[2]} schreit: {command[3]}"
        if command[1] == "001d":
            return f"Spieler: {command[2]} emote: {command[3]}"
        if command[1] == "003d":
            return f"NPC: {command[2]} sagt: {command[3]}"
        if command[1] == "0039":
            return f"Status: {command[2]}"
        if command[1] == "2040":
            return f"Award: {command[2]}"
        if command[1] == "0048":
            return f"Inhaltssuche: {command[2]}"
        if command[1] == "082b":
            return f"Cast_success: {command[2]}"
        if command[1] == "08ab":
            return f"Cast: {command[2]}"
        if command[1] == "08ae":
            return f"Buff aquired: {command[2]}"
        if command[1] == "08b0":
            return f"Buff lost: {command[2]}"
        if command[1] == "08ad":
            return f"Regen: {command[2]}"
        if command[1] == "0839":
            return f"Repair: {command[2]}"
        if command[1] == "0843":
            return f"Loot: {command[2]}"
        if command[1] == "08c3":
            return f"Fishing: {command[2]}"
        if command[1] == "0840":
            return f"XP: {command[2]}"
        if command[1] == "0bb9":
            return f"Quest angenommen: {command[2]}"
        
        
        return command

    if command[0] == "01":
        return f"Zone Change: {command[1]}"
    
    if command[0] == "02":
        return f"Player change: {command[1]}"
    
    if command[0] == "03":
        return f"New Player: {command[2]}"
    
    if command[0] == "04":
        return command
    
    if command[0] == "11":
        return f"PartyList: {command}"
        
    if command[0] == "26":
        return command
    
    if command[0] == "1A":
        return f"Real_Buff: {command}"
    
    if command[0] == "1E":
        return command
    
    if command[0] == "14":
        return command[2]
    
    if command[0] == "15":
        return f"Real_Cast: {command[2]} - {command[4]} -> {command[6]}"
    
    if command[0] == "16":
        return command
    
    if command[0] == "17":
        return command
    
    if command[0] == "18":
        return command
    
    if command[0] == "22":
        return command
    
    if command[0] == "25":
        return command
    
    if command[0] == "27":
        return
    
    if command[0] == "0C":
        return f"Player Stats: {command}"
    
    if command[0] == "FB":
        return f"ACT Info: {command[2]}"

    return command