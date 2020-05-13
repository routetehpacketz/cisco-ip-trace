#!/usr/bin/env python

import argparse
import ipcalc
import sys
from netmiko import ConnectHandler
import re
import getpass
from socket import gethostbyaddr


# error suppressing
class DevNull:
    def write(self, msg):
        pass


##########################################################################################################
#
#  Template and header for CSV
#
##########################################################################################################

csv_header = "Device IP,Reverse DNS Name,MAC Address,Switch,Port,Port Description,Interface Type,VLANs on port,Port MAC count\n"
csv_line_template = "{},{},{},{},{},{},{},\"{}\",{}\n"

##########################################################################################################
#
#  Define Global Regexs
#
##########################################################################################################
ip_regex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
subnet_regex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.')
mac_regex = re.compile(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}')
int_regex = re.compile(r'Fa{1}\S*\d/\S*\d{1,2}|Gi{1}\S*\d/\S*\d|Eth{1}\d/\S*\d{1,2}|Te{1}\S*\d/\S*\d')
int_po_regex = re.compile(r'Po{1}\d*')
int_regexes = [int_regex, int_po_regex]
description_regex = re.compile(r'Description: (.*)', re.MULTILINE)
access_vlan_regex = re.compile(r'switchport access vlan (\d*)', re.MULTILINE)
vlan_id_regex = re.compile(r'Vlan\d+')

##########################################################################################################
#
#  Get arguments from the command line
#
##########################################################################################################

# determine if arguments were passed to the script and parse if so
if len(sys.argv) > 1:

    parser = argparse.ArgumentParser()

    parser.add_argument('-n', action='store', dest='network_to_scan',
                        help='The network to scan in CIDR format example 192.168.10.0/24', required=True)

    parser.add_argument('-FA', action='store_true', dest='full_arp',
                        help='Enables full ARP table scan', required=False)

    parser.add_argument('-c', action='store', dest='core_switch',
                        help='The IP address of the core switch to start the scan from', required=True)

    parser.add_argument('-u', action='store', dest='username',
                        help='The username to connect with', required=True)

    parser.add_argument('-f', action='store', dest='filename',
                        help='Optional file to output results to', default="")

    parser.add_argument('-v', action='store', dest='vrf',
                        help='Optional VRF name', default="")

    try:
        options = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)
    password = getpass.getpass()
    secret = getpass.getpass("Enable password (leave blank if not needed): ")
    if options.vrf:
        current_vrf = options.vrf
        vrf = "vrf"
    else:
        current_vrf = ""
        vrf = ""
    if not options.full_arp and not options.network_to_scan:
        print("\nYou must use either the -n or -FA arguments.\n")
        parser.print_help()
        sys.exit(0)
# if no arguments parsed, run interactive prompts
else:
    options = None
    network_to_scan = input("Enter target in CIDR notation (192.168.10.0/24): ")
    while not re.match(subnet_regex, network_to_scan):
        network_to_scan = input("Enter target in CIDR notation (192.168.10.0/24): ")
    current_vrf = input("Enter VRF for the IP (leave blank if not needed): ")
    if current_vrf == "":
        vrf = ""
    else:
        vrf = "vrf"
    core_switch = input("Enter the IP address of the core router/switch that can ARP for the IP address to trace: ")
    while not re.match(ip_regex, core_switch):
        core_switch = input(
            "The entered value is not an IP address. Please re-enter the IP of the core router/switch: ")
    username = input("Username: ")
    password = getpass.getpass()
    secret = getpass.getpass("Enable password (leave blank if not needed): ")
    filename = input("Enter a filename to save output as CSV (leave blank for no file output): ")


##########################################################################################################
#
#  get_arp_table - Gets IPs from core router's ARP table
#
##########################################################################################################
def get_arp_table(core_switch, username, password, secret, current_vrf):
    core_switch_conn = ConnectHandler(device_type='cisco_ios', host=core_switch, username=username, password=password,
                                      secret=secret)
    core_switch_conn.enable()
    core_switch_conn.send_command("term len 0\n", delay_factor=.1)
    arp_table = core_switch_conn.send_command("show ip arp " + current_vrf + " | exc Incomplete\n", delay_factor=.1)
    arp_table = re.findall(ip_regex, arp_table)
    return arp_table


##########################################################################################################
#
#  get_mac_from_ip - finds the MAC address of an IP address via ARP
#
##########################################################################################################
def get_mac_from_ip(current_ip, core_switch, username, password, secret, current_vrf):
    # connect to core device
    core_switch_conn = ConnectHandler(device_type='cisco_ios', host=core_switch, username=username, password=password,
                                      secret=secret)

    core_switch_conn.enable()
    # ping IP to scan and obtain MAC
    core_switch_conn.send_command("ping " + vrf + " " + current_vrf + " " + current_ip + " rep 2\n", delay_factor=.1)
    show_ip_arp = core_switch_conn.send_command("show ip arp " + current_ip + "\n", delay_factor=.1)
    match_mac = re.search(mac_regex, show_ip_arp)

    core_switch_conn.disconnect()

    if match_mac:
        return match_mac.group()
    else:
        return False


##########################################################################################################
#
#  get_port_by_mac - finds switch port from the MAC address
#
##########################################################################################################
def get_port_by_mac(next_switch_conn, mac):
    mac_found = False
    multi_mac = False
    match_is_cdp_neighbor = False

    # find the port number of the mac address
    show_mac_table = next_switch_conn.send_command("show mac add add " + mac + " | inc " + mac, delay_factor=.1)
    mac_port = re.search(int_regexes[0], show_mac_table)
    # not found on a regular port, check etherchannels
    if not mac_port:
        mac_port = re.search(int_regexes[1], show_mac_table)
        if mac_port:
            mac_port = mac_port.group()
            etherchan_output = next_switch_conn.send_command("show etherchan summ | inc " + mac_port, delay_factor=.1)
            mac_port = re.search(int_regexes[0], etherchan_output)
    # if a mac is found, change from regex result to string
    if mac_port:
        mac_port = mac_port.group()
        return mac_port
    else:
        return False


##########################################################################################################
#
#  get_cdp_neighbor - Checks for CDP Neighbor on switch port
#
##########################################################################################################

def get_cdp_neighbor(next_switch_conn, mac_port):
    # Get the CDP neighbor IP
    show_cdp_nei = next_switch_conn.send_command("show cdp nei " + mac_port + " det | inc IP", delay_factor=.1)
    cdp_nei_ip = re.search(ip_regex, show_cdp_nei)
    if cdp_nei_ip:
        cdp_nei_ip = cdp_nei_ip.group()

    return cdp_nei_ip


##########################################################################################################
#
#  get_interface_description - Returns description of interface as a string
#
##########################################################################################################
def get_interface_description(next_switch_conn, mac_port):
    # get the interface description
    interface_description = ''

    show_interface_description = next_switch_conn.send_command("show interface " + mac_port + " | inc Description",
                                                               delay_factor=.1)
    interface_description_match = re.search(description_regex, show_interface_description)

    if interface_description_match:
        interface_description = interface_description_match.group(1)

    return interface_description


##########################################################################################################
#
#  get_interface_mode- Returns whether the interface is trunk or access and VLANs
#
##########################################################################################################
def get_interface_mode(next_switch_conn, mac_port):
    # check whether the interface is a trunk
    show_interface_trunk = next_switch_conn.send_command("show interface trunk | inc " + mac_port, delay_factor=.1)
    trunk_regex = re.compile(r'%s\s*(\S.*)' % mac_port, re.MULTILINE)
    interface_trunk_match = re.findall(trunk_regex, show_interface_trunk)
    # device is on a trunk port
    if interface_trunk_match:
        interface_type = "trunk"
        vlans = interface_trunk_match[-1]
    # device is on an access port
    else:
        interface_type = "access"
        show_run_interface = next_switch_conn.send_command("show run interface " + mac_port, delay_factor=.1)
        show_run_interface_match = re.search(access_vlan_regex, show_run_interface)
        if show_run_interface_match:
            vlans = show_run_interface_match.group(1)
        else:
            vlans = "1"  # no access vlan specified, so it must be 1

    return interface_type, vlans


##########################################################################################################
#
#  get_mac_count- Returns count of MAC addressed on a port
#
##########################################################################################################
def get_mac_count(next_switch_conn, mac_port):
    mac_port_macs = next_switch_conn.send_command("show mac add int " + mac_port + "\n", delay_factor=.1)

    multi_macs = re.findall(mac_regex, mac_port_macs)

    return len(multi_macs)


##########################################################################################################
#
#  trace_mac - Trace the MAC address through switches
#
##########################################################################################################
def trace_mac(mac, device_ip, dns_name, switch_ip, username, password, secret):
    # connect to switch
    next_switch_conn = ConnectHandler(device_type='cisco_ios', host=switch_ip, username=username, password=password,
                                      secret=secret)
    next_switch_hostname = next_switch_conn.find_prompt().rstrip("#>")
    next_switch_conn.enable()

    # Find port that has MAC address
    port = get_port_by_mac(next_switch_conn, mac)
    # No port found, return
    if not port:
        next_switch_conn.disconnect()
        print("Port Unknown")
        line = "{},{},{},{},Unknown\n".format(device_ip, dns_name, mac, next_switch_hostname)
        return line

    description = get_interface_description(next_switch_conn, port)
    interface_type, vlans = get_interface_mode(next_switch_conn, port)
    mac_count = get_mac_count(next_switch_conn, port)

    # See if port is another Cisco device, if it is, start tracing on that switch
    cdp_nei_ip = get_cdp_neighbor(next_switch_conn, port)
    if cdp_nei_ip:
        sys.stderr = DevNull()
        try:
            line = trace_mac(mac, device_ip, dns_name, cdp_nei_ip, username, password, secret)
        except:
            next_switch_conn.disconnect()
            print("error:\n")
            print("Traced to CDP neighbor " + cdp_nei_ip + ", but could not SSH into it.\n")
            line = csv_line_template.format(device_ip, dns_name, mac, next_switch_hostname, port, description,
                                            interface_type, vlans, str(mac_count))
            return line

    # Build line to print
    else:
        # Status output
        print("complete!\n")

        # Gather intformation on the final port
        description = get_interface_description(next_switch_conn, port)
        interface_type, vlans = get_interface_mode(next_switch_conn, port)
        mac_count = get_mac_count(next_switch_conn, port)

        line = csv_line_template.format(device_ip, dns_name, mac, next_switch_hostname, port, description,
                                        interface_type, vlans, str(mac_count))

    next_switch_conn.disconnect()

    return line


##########################################################################################################
#
#  trace_ip_address - Trace the MAC address through switches
#
##########################################################################################################
def trace_ip_address(ipaddress_ipcalc):
    # Get the MAC address from the core via ARP
    ipaddress = str(ipaddress_ipcalc)
    dns_name = None
    try:
        dns_name = gethostbyaddr(ipaddress)[0]
    except:
        pass
    if not dns_name:
        dns_name = "N/A"
    print("\nTracing " + ipaddress + "...", end="")
    # if using script arguments
    if options:
        mac = get_mac_from_ip(ipaddress, options.core_switch, options.username, password, secret, options.vrf)
    # if using prompts
    else:
        mac = get_mac_from_ip(ipaddress, core_switch, username, password, secret, vrf)

    # If we can find the MAC start tracing
    if mac:
        # if using script arguments
        if options:
            line = trace_mac(mac, ipaddress, dns_name, options.core_switch, options.username, password, secret)
        # if using prompts
        else:
            line = trace_mac(mac, ipaddress, dns_name, core_switch, username, password, secret)
    # otherwise move on to the next IP address
    else:
        print("MAC not found in ARP")
        line = "{},Not Found\n".format(ipaddress)

    return line


##########################################################################################################
#
#  Main function
#
##########################################################################################################

def main():
    # if using script arguments
    if options:
        if options.full_arp:
            arp_targets = get_arp_table(options.core_switch, options.username, password, secret, options.vrf)
            # if outputting to csv with arguments
            if options.filename:
                # Open the CSV and print the header
                csv_file = open(options.filename, "w")
                csv_file.write(csv_header)
                for ipaddress_ipcalc in arp_targets:
                    line = trace_ip_address(ipaddress_ipcalc)
                    print(line)
                    csv_file.write(line)
            else:
                for ipaddress_ipcalc in arp_targets:
                    line = trace_ip_address(ipaddress_ipcalc)
                    print(line)
    # if outputting to csv with prompts
    elif filename:
        csv_file = open(filename, "w")
        csv_file.write(csv_header)
        # Loop over each IP in the network and trace
        for ipaddress_ipcalc in ipcalc.Network(network_to_scan):
            line = trace_ip_address(ipaddress_ipcalc)
            print(csv_header + line)
            csv_file.write(line)
    # just print lines if not outputting to csv
    else:
        for ipaddress_ipcalc in ipcalc.Network(network_to_scan):
            line = trace_ip_address(ipaddress_ipcalc)
            print(csv_header + line)


main()
