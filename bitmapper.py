
# Source: https://github.com/MattTW/HoneyAlarmServer/blob/4b347955936b37d81c917d02fc5ec8cfec7b74fb/alarmserver.py#L445
# Source: https://github.com/MattTW/HoneyAlarmServer/blob/master/bitmapper.py

import re

def zoneHexString2Bitmask(aHexStringInt):
    bitfieldString = ''
    bigEndianHexString = ''
    # every four characters
    inputItems = re.findall('....', aHexStringInt)
    for inputItem in inputItems:
        # Swap the couples of every four bytes
        # (little endian to big endian)
        swappedBytes = []
        swappedBytes.insert(0, inputItem[0:2])
        swappedBytes.insert(0, inputItem[2:4])

        # add swapped set of four bytes to our return items,
        # converting from hex to int
        bigEndianHexString += ''.join(swappedBytes)

        # convert hex string to 64 bit bitstring
        bitfieldString = str(bin(int(bigEndianHexString, 16))[2:].zfill(64))

    # reverse every 16 bits so "lowest" zone is on the left
    zonefieldString = ''
    inputItems = re.findall('.' * 16, bitfieldString)
    for inputItem in inputItems:
        zonefieldString += inputItem[::-1]

    return zonefieldString

def handle_zone_state_change(data):
    # Envisalink TPI is inconsistent at generating these
    fullZoneBitmask = ''

    #envisalink 4 returns 128 bits for zone bitmask, bin function used
    #conversion logic assumes 64 bit int so break it in two and combine the parts.
    fullZoneBitmask = zoneHexString2Bitmask(data[0:16])
    fullZoneBitmask += zoneHexString2Bitmask(data[16:])

    print('Expanded string: ' + str(fullZoneBitmask))

    for zoneNumber, zoneBit in enumerate(fullZoneBitmask, start=1):
        #print "(zone %i) is %s" % (zoneNumber, "Open/Faulted" if zoneBit == '1' else "Closed/Not Faulted")
        if zoneBit == '1':
            zoneBypassState = 'bypassed'
            print('(zone ' + str(zoneNumber) + ') is ' + zoneBypassState)

        else:
            zoneBypassState = 'not bypassed'
            #print('(zone ' + str(zoneNumber) + ') is ' + zoneBypassState)

#while True:
data = input("Envisalink string to decode: ")
handle_zone_state_change(data)
#handle_zone_state_change('0040000000000000')
