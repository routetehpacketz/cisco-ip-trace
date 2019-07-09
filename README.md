## Cisco IP Trace

This Python script will take a single IP address or a range within a /24 and trace the associated MAC address(es) from a core Cisco router/switch to the edge switch port. It will output the provided IP address, MAC address, edge switch name, and port name on the console.

Please note that this script is only designed to run on Cisco IOS and NX-OS devices.

### Usage

Open a command prompt/terminal and run cisco_ip_trace.py 


usage: cisco_ip_trace.py [-h] -n NETWORK_TO_SCAN -c CORE_SWITCH -u USERNAME -f
                         FILENAME [-v VRF]

optional arguments:
  -h, --help          show this help message and exit
  -n NETWORK_TO_SCAN  The network to scan in CIDR format example
                      192.168.10.0/24
  -c CORE_SWITCH      The IP address of the core switch to start the scan from
  -u USERNAME         The username to connect with
  -f FILENAME         The file to output results to
  -v VRF              Optional VRF name


The script will then use a series of show commands and regexes against the show command outputs to identify the port the associated MAC address is learned on, determine if there is another Cisco switch connected via CDP, and continues the trace until it reaches a port where no switch is detected. It will then print its findings like this:

`10.1.10.185,0123.4567.6d36,SwitchB,Gi1/0/2`

The script will alert you if multiple MAC addresses are currently found on the edge port. This is just extra info in case it helps narrow down a device:

```
Note: More than one MAC found on this port, possible unmanaged switch present.

10.1.10.184,abcd.4567.2fc2,SwitchA,Gi2/0/30
```

The script will also alert you if the provided IP *is a CDP neighbor*. Currently this will not provide you port information past the core router/switch:

```
Note: The IP provided is a CDP neighbor.

10.1.1.10,0124.abcd.1234,CoreA,Gi4/1
```

### Requirements

-Python3.x

-Python module 'netmiko'

-SSH access to all Cisco devices from the computer running the script; Telnet is **not supported**

-Cisco Discovery Protocol (CDP) enabled on all Cisco switches

-The credentials provided must work on **all** devices discovered via CDP

-The "core" device that will be ARPing for the IP in question must have layer 2 connectivity to the LAN on which the target device is connected or the CDP neighbor discovery process will fail

### Known issues/to-do

-Add prompt for new creds if supplied creds fail on a discovered neighbor

-Add support for Cisco Nexus switches with port-channels (just need to work out the command syntax difference)

-LLDP support

-Option to output range scan to a CSV file

##### I appreciate any and all feedback.
