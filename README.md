## Cisco IP Trace

This Python script will take a single IP address or a range within a /24 and trace the associated MAC address(es) from a core Cisco router/switch to the edge switch port. It will output the provided IP address, MAC address, edge switch name, and port name on the console.

Please note that this script is only designed to run on Cisco IOS and NX-OS devices.

### Usage

1. Open a command prompt/terminal and run cisco_ip_trace.py 

2. Choose between scanning a single IP address or a range.

```
Do you want to scan a single IP or a range?

1. Single IP

2. Range (must be contiguous; no greater than /24)

Please input 1 or 2:
```

Single IP:

```
Enter IP address to trace: 10.1.10.184
Enter the IP address of the core router/switch that can ARP for the IP address to trace: 10.1.1.1
Username: admin
Password: ********
```

Range of IPs:

```
Enter first three octets of subnet you'd like to scan (ex. 10.1.1.): 10.1.10
Enter last octet of first IP in the range to scan: 184
Enter the last octet of the last IP in the range to scan: 187
Enter the IP address of the core router/switch that can ARP for the IP address to trace: 10.1.1.1
Username: admin
Password: *********
```

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

-Python module 'paramiko'

-SSH access to all Cisco devices from the computer running the script; Telnet is **not supported**

-Cisco Discovery Protocol (CDP) enabled on all Cisco switches

-The credentials provided must work on **all** devices discovered via CDP

-The "core" device that will be ARPing for the IP in question must have layer 2 connectivity to the LAN on which the target device is connected or the CDP neighbor discovery process will fail

### Known issues/to-do

-Enhanced input validation

-Range scanning for subnet greater than /24

-Add prompt for new creds if supplied creds fail on a discovered neighbor

-Fix issue when provided IP is a CDP neighbor and trace doesn't report past core

-Add support for Cisco Nexus switches with port-channels (just need to work out the command syntax difference)

-LLDP support

-Option to output range scan to a CSV file

-Fixed error when <a href="https://github.com/routetehpacketz/cisco-ip-trace/issues/1">the initial port the device is found on is a routed port</a>

##### I appreciate any and all feedback.
