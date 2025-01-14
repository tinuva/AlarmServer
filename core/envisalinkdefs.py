"""Alarm Server
Supporting Envisalink 2DS/3/4
Written by donnyk+envisalink@gmail.com
This code is under the terms of the GPL v3 license."""

# pylint: disable=line-too-long

EVL_DEFAULTS = {
	   'zone' : {'open' : False, 'fault' : False, 'alarm' : False, 'tamper' : False, 'bypass' : False},
	   'partition' : {'ready' : False, 'trouble' : False, 'exit_delay' : False, 'entry_delay' : False, 'armed' : False, 'armed_bypass' : False, 'alarm' : False, 'tamper' : False, 'chime' : False, 'trouble_led' : False},
	   'system' : {'fire_key_alarm' : False, 'aux_key_alarm' : False, 'panic_key_alarm' : False, '2wire_alarm' : False, 'battery_trouble' : False, 'ac_trouble' : False, 'system_bell_trouble' : False, 'system_tamper' : False, 'fire_trouble' : False}
}

EVL_COMMANDS = {
    'KeepAlive' : '000',
    'StatusReport' : '001',
    'DumpZoneTimers' : '008',
    'PartitionKeypress' : '071',
    'Disarm' : '040',
    'ArmStay' : '031',
    'ArmAway' : '030',
    'ArmMax' : '032',
    'Login' : '005',
    'Panic' : '060',
    'SendCode' : '200',
    'CommandOutput' : '020',
    'SetTime' : '010'
}

EVL_ARMMODES = {
    0 : 'Away',
    1 : 'Stay',
    2 : 'Zero Entry Away',
    3 : 'Zero Entry Stay'
}

EVL_LEDBITMASK = {
    0x80 : "Backlight",
    0x40 : "Fire",
    0x20 : "Program",
    0x10 : "Trouble",
    0x08 : "Bypass",
    0x04 : "Memory",
    0x02 : "Armed",
    0x01 : "Ready"
    }

EVL_VERBOSETROUBLEBITMASK = {
    0x80 : "Loss of Time",
    0x40 : "Zone Low Battery",
    0x20 : "Zone Tamper",
    0x10 : "Zone Fault",
    0x08 : "Failure to Communicate",
    0x04 : "Telephone Line Fault",
    0x02 : "AC Power Lost",
    0x01 : "Service is Required"
    }

EVL_RESPONSETYPES = {

    505 : {'name' : 'Login Interaction {0}', 'description' : 'Sent During Session Login Only.', 'handler' : 'login'},
    615 : {'name' : 'Envisalink Zone Timer Dump', 'description' : 'This command contains the raw zone timers used inside the Envisalink. The dump is a 256 character packed HEX string representing 64 UINT16 (little endian) zone timers. Zone timers count down from 0xFFFF (zone is open) to 0x0000 (zone is closed too long ago to remember). Each ''tick'' of the zone time is actually 5 seconds so a zone timer of 0xFFFE means ''5 seconds ago''. Remember, the zone timers are LITTLE ENDIAN so the above example would be transmitted as FEFF.'},
    500 : {'name' : 'Command Acknowledge {0}', 'description' : 'A command has been received successfully.'},
    501 : {'name' : 'Command Error', 'description' : 'A command has been received with a bad checksum.'},
    900 : {'name' : 'Code Required', 'description' : 'This command will tell the API to enter an access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},
    912 : {'name' : 'Command Output Pressed Partition {0[0]} Command {0[1]}', 'description' : 'This command will tell the API to enter an access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},

#ZONE UPDATES
    601 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Alarm', 'description' : 'A zone has gone into alarm.', 'handler' : 'zone', 'status' : {'alarm' : True}},
    602 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Alarm Restore', 'description' : 'A zone alarm has been restored.', 'handler' : 'zone', 'status' : {'alarm' : False}},
    603 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Tamper', 'description' : 'A zone has a tamper condition.', 'handler' : 'zone', 'status' : {'tamper' : True}},
    604 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Tamper Restore', 'description' : 'A zone tamper condition has been restored.', 'handler' : 'zone', 'status' : {'tamper' : False}},
    605 : {'type' : 'zone', 'name' : 'Zone {0} Fault', 'description' : 'A zone has a fault condition.', 'status' : {'fault' : True}},
    606 : {'type' : 'zone', 'name' : 'Zone {0} Fault Restore', 'description' : 'A zone fault condition has been restored.', 'status' : {'fault' : False}},
    609 : {'type' : 'zone', 'name' : 'Zone {0} Open', 'description' : 'General status of the zone.', 'status' : {'open' : True}},
    610 : {'type' : 'zone', 'name' : 'Zone {0} Restored', 'description' : 'General status of the zone.', 'status' : {'open' : False}},

#PARTITION UPDATES
    650 : {'type' : 'partition', 'name' : 'Partition {0} Ready', 'description' : 'Partition can now be armed (all zones restored, no troubles, etc). Also issued at the end of Bell Timeout if the partition was READY when an alarm occurred.', 'status' : {'ready' : True, 'pgm_output' : False}},
    651 : {'type' : 'partition', 'name' : 'Partition {0} Not Ready', 'description' : 'Partition cannot be armed (zones open, trouble present, etc).', 'status' : {'ready' : False}},
    652 : {'type' : 'partition', 'name' : 'Partition {0} Armed Mode {1}', 'description' : 'Partition has been armed - sent at the end of exit delay Also sent after an alarm if the Bell Cutoff Timer expires Mode is appended to indicate whether the partition is armed AWAY, STAY, ZERO-ENTRY-AWAY, or ZERO-ENTRY-STAY.', 'handler' : 'partition', 'status' : {'armed' : True, 'exit_delay' : False, 'ready' : False}},
    653 : {'type' : 'partition', 'name' : 'Partition {0} Ready - Force Arming Enabled', 'description' : 'Partition can now be armed (all zones restored, no troubles, etc). Also issued at the end of Bell Timeout if the partition was READY when an alarm occurred.', 'status' : {'ready' : True}},
    654 : {'type' : 'partition', 'name' : 'Partition {0} In Alarm', 'description' : 'A partition is in alarm.', 'status' : {'alarm' : True}},
    655 : {'type' : 'partition', 'name' : 'Partition {0} Disarmed', 'description' : 'A partition has been disarmed.', 'status' : {'alarm' : False, 'armed' : False, 'exit_delay' : False, 'entry_delay' : False}},
    656 : {'type' : 'partition', 'name' : 'Partition {0} Exit Delay in Progress', 'description' : 'A partition is in Exit Delay.', 'status' : {'exit_delay' : True}},
    657 : {'type' : 'partition', 'name' : 'Partition {0} Entry Delay in Progress', 'description' : 'A partition is in Entry Delay.', 'status' : {'entry_delay' : True}},
    663 : {'type' : 'partition', 'name' : 'Partition {0} Chime Enabled', 'description' : 'The door chime feature has been enabled.', 'status' : {'chime' : True}},
    664 : {'type' : 'partition', 'name' : 'Partition {0} Chime Disabled', 'description' : 'The door chime feature has been disabled.', 'status' : {'chime' : False}},
    673 : {'type' : 'partition', 'name' : 'Partition {0} is Busy', 'description' : 'The partition is busy (another keypad is programming or an installer is programming).'},
    700 : {'type' : 'partition', 'name' : 'Partition {0} User {1} Closing', 'description' : 'A partition has been armed by a user - sent at the end of exit delay.', 'handler' : 'partition', 'status' : {'armed' : True, 'exit_delay' : False}},
    750 : {'type' : 'partition', 'name' : 'Partition {0} User {1} Opening', 'description' : 'A partition has been disarmed by a user.', 'handler' : 'partition', 'status' : {'armed' : False, 'entry_delay' : False}},
    751 : {'type' : 'partition', 'name' : 'Partition {0} Special Opening', 'description' : 'A partition has been disarmed by one of the following methods: Keyswitch, DLS software, Wireless Key.', 'status' : {'armed' : False, 'entry_delay' : False}},
    840 : {'type' : 'partition', 'name' : 'Partition {0} Trouble LED ON', 'description' : 'This command shows the general trouble status that the trouble LED on a keypad normally shows. When ON, it means there is a trouble on this partition. This command when the LED transitions from OFF, to ON.', 'status' : {'trouble' : True}},
    841 : {'type' : 'partition', 'name' : 'Partition {0} Trouble LED OFF', 'description' : 'This command shows the general trouble status that the trouble LED on a keypad normally shows. When the LED is OFF, this usually means there are no troubles present on this partition but certain modes will blank this LED even in the presence of a partition trouble. This command when the LED transitions from ON, to OFF.', 'status' : {'trouble' : False}},

#GENERAL UPDATES
    621 : {'type' : 'system', 'name' : '[F] Key Alarm', 'description' : 'A Fire key alarm has been detected.', 'status' : {'fire_key_alarm' : True}},
    622 : {'type' : 'system', 'name' : '[F] Key Alarm', 'description' : 'A Fire key alarm has been restored (sent automatically).', 'status' : {'fire_key_alarm' : False}},
    623 : {'type' : 'system', 'name' : '[A] Key Alarm', 'description' : 'A Auxillary key alarm has been detected.', 'status' : {'aux_key_alarm' : True}},
    624 : {'type' : 'system', 'name' : '[A] Key Alarm', 'description' : 'A Auxillary key alarm has been restored (sent automatically).', 'status' : {'aux_key_alarm' : False}},
    625 : {'type' : 'system', 'name' : '[P] Key Alarm', 'description' : 'A Panic key alarm has been detected.', 'status' : {'panic_key_alarm' : True}},
    626 : {'type' : 'system', 'name' : '[P] Key Alarm', 'description' : 'A Panic key alarm has been restored (sent automatically).', 'status' : {'panic_key_alarm' : False}},
    631 : {'type' : 'system', 'name' : '2-Wire Smoke/Aux Alarm', 'description' : 'A 2-wire smoke/Auxiliary alarm has been activated.', 'status' : {'2wire_alarm' : True}},
    632 : {'type' : 'system', 'name' : '2-Wire Smoke/Aux Restore', 'description' : 'A 2-wire smoke/Auxiliary alarm has been restored.', 'status' : {'2wire_alarm' : False}},
    660 : {'type' : 'partition', 'name' : 'Partition {0} PGM Output is in Progress', 'description' : '*71, *72, *73, or *74 has been pressed.', 'status': {'pgm_output' : True}},
    800 : {'type' : 'system', 'name' : 'Panel Battery Trouble', 'description' : 'The panel has a low battery.', 'status' : {'battery_trouble' : True}},
    801 : {'type' : 'system', 'name' : 'Panel Battery Trouble Restore', 'description' : 'The panel''s low battery has been restored.', 'status' : {'battery_trouble' : False}},
    802 : {'type' : 'system', 'name' : 'Panel AC Trouble', 'description' : 'AC power to the panel has been removed.', 'status' : {'ac_trouble' : True}},
    803 : {'type' : 'system', 'name' : 'Panel AC Restore', 'description' : 'AC power to the panel has been restored.', 'status' : {'ac_trouble' : False}},
    829 : {'type' : 'system', 'name' : 'General System Tamper', 'description' : 'A tamper has occurred with one of the following modules: Zone Expander, PC5132, PC5204, PC5208, PC5400, PC59XX, LINKS 2X50, PC5108L, PC5100, PC5200.', 'status' : {'system_tamper' : True}},
    830 : {'type' : 'system', 'name' : 'General System Tamper Restore', 'description' : 'A general system Tamper has been restored.', 'status' : {'system_tamper' : False}},
    849 : {'name' : 'Verbose Trouble Status {0}', 'description' : 'This command is issued when a trouble appears on the system and roughly every 5 minutes until the trouble is cleared. The two characters are a bitfield (similar to 510,511). The meaning of each bit is the same as what you see on an LED keypad (see the user manual).'},

#ZONE BYPASS UPDATES
    616 : {'type' : 'zone', 'handler':'zone_bypass_update', 'name' : 'Zone bypass update', 'description' : 'This command is issued upon leaving Zone Bypass programming (*1 on the keypad). It is a 16 character HEX string representing an 8 byte bitfield. The bitfield indicates which zones are currently in bypass. A "1" indicates the zone is in bypass. The lower 8 zones are in the first position of the bitfield. The developer can force this dump by using the keystring commands to enter and leave zone bypassing, i.e. "*1#"'},

#UPDATES not part of pyenvisalink
    502 : {'name' : 'System Error {0}', 'description' : 'An error has been detected.'},
    510 : {'name' : 'Keypad Led State - Partition 1', 'description' : 'Outputted when the TPI has deceted a change of state in the Partition 1 keypad LEDs.'},
    511 : {'name' : 'Keypad Led Flash State - Partition 1', 'description' : 'Outputed when the TPI has detected a change of state in the Partition 1 keypad LEDs as to whether to flash or not. Overrides 510. That is, if 511 says the PROGRAM LED is flashing, then it doesn''t matter what 510 says.'},
    550 : {'name' : 'Time/Date Broadcast {0[4]}{0[5]}/{0[6]}{0[7]}/{0[8]}{0[9]} {0[0]}{0[1]}:{0[2]}{0[3]}', 'description' : 'Outputs the current security system time.'},
    560 : {'name' : 'Ring Detected', 'description' : 'The Panel has detected a ring on the telephone line. Note: This command will only be issued if an ESCORT 5580xx module is present.'},
    561 : {'name' : 'Indoor Temperature Broadcast {0}', 'description' : 'If an ESCORT 5580TC is installed, and at least one ENERSTAT thermostat, this command displays the interior temperature and the thermostat number.'},
    562 : {'name' : 'Outdoor Temperature Broadcast {0}', 'description' : 'If an ESCORT 5580TC is installed, and at least one ENERSTAT thermostat, this command displays the exterior temperature and the thermostat number.'},
    620 : {'name' : 'Duress Alarm', 'description' : 'A duress code has been entered on a system keypad.'},
    658 : {'type' : 'partition', 'name' : 'Partition {0} Keypad Lock-out', 'description' : 'A partition is in Keypad Lockout due to too many failed user code attempts.'},
    659 : {'type' : 'partition', 'name' : 'Partition {0} Failed to Arm', 'description' : 'An attempt to arm the partition has failed.'},
    670 : {'type' : 'partition', 'name' : 'Partition {0} Invalid Access Code', 'description' : 'Invalid Access Code.'},
    671 : {'type' : 'partition', 'name' : 'Partition {0} Function Not Available', 'description' : 'A partition is in Entry delay.'},
    672 : {'type' : 'partition', 'name' : 'Partition {0} Failure to Arm', 'description' : 'An attempt was made to arm the partition and it failed.'},
    674 : {'type' : 'partition', 'name' : 'Partition {0} System Arming in Progress', 'description' : 'This system is auto-arming and is in arm warning delay.'},
    680 : {'name' : 'System in installers mode', 'description' : 'System has entered installers mode'},
    701 : {'type' : 'partition', 'name' : 'Partition {0} Special Closing', 'description' : 'A partition has been armed by one of the following methods: Quick Arm, Auto Arm, Keyswitch, DLS software, Wireless Key.', 'status' : {'armed' : True, 'exit_delay' : False}},
    702 : {'type' : 'partition', 'name' : 'Partition {0} Partial Closing', 'description' : 'A partition has been armed but one or more zones have been bypassed.', 'status' : {'armed' : True, 'exit_delay' : False}},
    806 : {'type' : 'system', 'name' : 'System Bell Trouble', 'description' : 'An open circuit has been detected across the bell terminals.', 'status' : {'system_bell_trouble' : True}},
    807 : {'type' : 'system', 'name' : 'System Bell Trouble Restoral', 'description' : 'The bell trouble has been restored.', 'status' : {'system_bell_trouble' : False}},
    814 : {'name' : 'FTC Trouble', 'description' : 'The panel has failed to communicate successfully to the monitoring station.'},
    816 : {'name' : 'Buffer Near Full', 'description' : 'Sent when the panel''s Event Buffer is 75% full from when it was last uploaded to DLS.'},
    842 : {'type' : 'system', 'name' : 'Fire Trouble Alarm', 'description' : 'Fire Trouble Alarm', 'status' : {'fire_trouble' : True}},
    843 : {'type' : 'system', 'name' : 'Fire Trouble Alarm Restore', 'description' : 'Fire Trouble Alarm Restore', 'status' : {'fire_trouble' : False}},
    921 : {'name' : 'Master Code Required', 'description' : 'This command will tell the API to enter a master access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},
    922 : {'name' : 'Installers Code Required', 'description' : 'This command will tell the API to enter an installers access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'}
}
