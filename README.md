## Cisco IP Trace

This Python script will allow you to enter a single IP or CIDR network range and trace the associated MAC address(es) from a core Cisco router/switch to the edge switch port. It will output the target IP address, MAC address, edge switch name, port name, port description, interface mode (access or trunk), VLAN(s) allowed on port, and the number of MAC addresses currently learned on the edge port. By default the script will output this information to the console, but you can optionally output to CSV.

Please note that this script is only designed to run on Cisco IOS and NX-OS devices.

### Usage

Open a command prompt/terminal and run cisco_ip_trace.py. The script has two options to run it: interactive prompts or parameters. 

These are the parameters that may be passed to the script:
```
usage: cisco_ip_trace.py [-h] -n NETWORK_TO_SCAN -c CORE_SWITCH -u USERNAME -f
                         FILENAME [-v VRF]

optional arguments:
  -h, --help          show this help message and exit
  -n NETWORK_TO_SCAN  The network to scan in CIDR format example
                      192.168.10.0/24
  -c CORE_SWITCH      The IP address of the core switch to start the scan from
  -u USERNAME         The username to connect with
  -f FILENAME         Optional file to output results to
  -v VRF              Optional VRF name
```
If no parameters are provided, the script will run with interactive prompts:

```
Enter target in CIDR notation (192.168.10.0/24): 192.168.10.0/24
Enter VRF for the IP. Press 'Enter' if you're not using VRFs: myvrf
Enter the IP address of the core router/switch that can ARP for the IP address to trace: 192.168.10.1
Username: admin
Password: *****
Enable password (leave blank if not needed):
Enter a filename to save output as CSV (leave blank for no file output): myfile.csv
```

The script will then use a series of show commands and regexes against the show command outputs to identify the port the associated MAC address is learned on, determine if there is another Cisco switch connected via CDP, and continues the trace until it reaches a port where no switch is detected. It will then print its findings like this:

```
Tracing 192.168.10.10...complete!

Device IP,MAC Address,Switch,Port,Port Description,Interface Type,VLANs on port,Port MAC count
192.168.10.10,0123.4567.6d36,SwitchB,Gi1/0/2,My Description,access,"1",1
```

### Requirements

-Python3.x

-Python modules 'netmiko' and 'argparse'

-SSH access to all Cisco devices from the computer running the script

-Cisco Discovery Protocol (CDP) enabled on all Cisco switches

-The credentials provided must work on **all** devices discovered via CDP

-The "core" device that will be ARPing for the IP in question must have layer 2 connectivity to the LAN on which the target device is connected or the CDP neighbor discovery process will fail

### Known issues/to-do

-Add prompt for new creds if supplied creds fail on a discovered neighbor

-LLDP support

##### I appreciate any and all feedback.
