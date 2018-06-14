## Cisco IP Trace

This is a basic Python script that takes an IP address and traces its MAC address from a core device to its edge port. It will then output the IP, MAC address, edge switch name, and port name on the console.

### Usage

1. Open a command prompt/terminal and run cisco_ip_trace.py 

2. Fill out the following prompts:

```
Enter the IP address of the core router/switch that can ARP for the IP address to scan:

Enter IP address to trace:

Username:

Password:
```

3. Press Enter

The script will then use a series of show commands and regexes against the show command outputs to identify the port the associated MAC address is learned on, determine if there is another Cisco switch connected via CDP, and continues the trace until it reaches a port where no switch is detected. It will then print its findings like this:

`10.1.10.10,000.abcd.ef12,SwitchA,Gi1/0/1`

### Requirements

-Python3.x (~~I haven't tested this in Python2.x, so it may work without any syntax adjustments~~ -Python2.x does not support the use of `nonlocal` so Python3 **is** required)

-Python module 'paramiko'

-SSH access to your Cisco devices (telnet is not supported)

-Cisco Discovery Protocol (CDP) enabled on all Cisco switches 

-The credentials provided must work on *all* devices

-The "core" device that will be ARPing for the IP in question must have layer 2 connectivity to the LAN on which the target device is connected or the CDP neighbor discovery process will fail

### Known issues/to-do

-Option to choose between scanning a single IP or a range

-Handling for when the target IP *is* a Cisco CDP neighbor; currently the script will end with a `NoneType` error

-Add support for Cisco Nexus switches with port-channels (just need to work out the command syntax difference)

-LLDP support

-Detection of possible unmanaged/non-CDP switch on edge port (basically determine if multiple MAC addresses are learned); this would just be an added FYI to help track down a device


##### I appreciate any and all feedback.
