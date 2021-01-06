#!/usr/bin/env python

import argparse
import ipaddress
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
int_regex = re.compile(r'Fa\S*\d/\S*\d{1,2}|Gi\S*\d/\S*\d|Eth\d/\S*\d{1,2}|Te\S*\d/\S*\d|Fo\S*\d/\S*\d')
int_po_regex = re.compile(r'Po\d*')
int_regexes = [int_regex, int_po_regex]
description_regex = re.compile(r'Description: (.*)', re.MULTILINE)
access_vlan_regex = re.compile(r'switchport access vlan (\d*)', re.MULTILINE)

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
#  get_cdp_neighbor - Checks for CDP Neighbor on switch port
#
##########################################################################################################

def get_cdp_neighbor(next_switch_conn, mac_port):
    show_cdp_nei = next_switch_conn.send_command("show cdp nei " + mac_port + " det | inc IP", delay_factor=.1)
    cdp_nei_ip = re.search(ip_regex, show_cdp_nei)
    return cdp_nei_ip


##########################################################################################################
#
#  get_port_by_mac - finds switch port from the MAC address
#
##########################################################################################################
def get_port_by_mac(ssh_conn, mac):
    # find the port number of the target MAC address
    show_mac_table = ssh_conn.send_command("show mac add add " + mac + " | inc " + mac, delay_factor=.1)
    mac_port = re.search(int_regexes[0], show_mac_table)
    # not found on a regular port, check etherchannels
    if not mac_port:
        mac_port = re.search(int_regexes[1], show_mac_table)
        if mac_port:
            mac_port = mac_port.group()
            etherchan_output = ssh_conn.send_command("show etherchan summ | inc " + mac_port, delay_factor=.1)
            mac_port = re.search(int_regexes[0], etherchan_output)
            return mac_port.group()
    # if a mac is found, change from regex result to string
    if mac_port:
        return mac_port.group()
    else:
        return False

##########################################################################################################
#
#  get_interface_desc - Returns description of interface as a string
#
##########################################################################################################
def get_interface_desc(next_switch_conn, mac_port):
    # get the interface description
    interface_description = ''

    show_interface_description = next_switch_conn.send_command("show interface " + mac_port + " | inc Description",
                                                               delay_factor=.1)
    interface_description_match = re.search(description_regex, show_interface_description)

    if interface_description_match:
        interface_description = interface_description_match.group(1)
    # strip commas from description to keep CSV formatting
    interface_description.replace(',','')
    return interface_description


##########################################################################################################
#
#  get_interface_mode - Returns whether the interface is trunk or access and VLANs
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
def trace_mac(mac, target_ip, dns_name, switch_ip, username, password, secret):
    # connect to switch
    switch_conn = ConnectHandler(device_type='cisco_ios', host=switch_ip, username=username, password=password,
                                      secret=secret)
    switch_hostname = switch_conn.find_prompt().rstrip("#>")
    switch_conn.enable()

    port = get_port_by_mac(switch_conn, mac)

    # Check current port for a CDP neighbor IP and continue if one is found
    cdp_nei_ip = get_cdp_neighbor(switch_conn, port)
    if cdp_nei_ip:
        cdp_nei_ip = cdp_nei_ip.group()
        try:
            sys.stderr = DevNull()
            line = trace_mac(mac, target_ip, dns_name, cdp_nei_ip, username, password, secret)
        # ends script with alert if SSH login fails to CDP neighbor
        except:
            switch_conn.disconnect()
            print("error:\n")
            print("Traced to CDP neighbor " + cdp_nei_ip + ", but could not SSH into it.\n")
            description = get_interface_desc(switch_conn, port)
            interface_type, vlans = get_interface_mode(switch_conn, port)
            mac_count = get_mac_count(switch_conn, port)
            line = csv_line_template.format(target_ip, dns_name, mac, switch_hostname, port, description,
                                            interface_type, vlans, str(mac_count))
            return line

    # end when no further CDP neighbors can be found
    else:
        # Update status in console
        print("complete!\n")

        # Gather info on the final port
        description = get_interface_desc(switch_conn, port)
        interface_type, vlans = get_interface_mode(switch_conn, port)
        mac_count = get_mac_count(switch_conn, port)

        line = csv_line_template.format(target_ip, dns_name, mac, switch_hostname, port, description,
                                        interface_type, vlans, str(mac_count))

    switch_conn.disconnect()

    return line


##########################################################################################################
#
#  check_core - Obtains MAC of target IP and initial device port, checks for first CDP neighbor
#
##########################################################################################################
def check_core(current_ip, core_router, username, password, secret, current_vrf):
    # connect to core device
    core_conn = ConnectHandler(device_type='cisco_ios', host=core_router, username=username, password=password,
                                      secret=secret)
    # obtain hostname of core device
    core_router_hostname = core_conn.find_prompt()
    core_conn.enable()
    # ping IP and check ARP table for MAC
    core_conn.send_command("ping " + vrf + " " + current_vrf + " " + current_ip + " rep 2\n", delay_factor=.1)
    show_ip_arp = core_conn.send_command("show ip arp " + current_ip + "\n", delay_factor=.1)
    match_mac = re.search(mac_regex, show_ip_arp)
    # if MAC is found, obtain learned port and check for CDP neighbor
    if match_mac:
        match_mac = match_mac.group()
        port = re.search(int_regex, show_ip_arp)
        if not port:
            port = get_port_by_mac(core_conn, match_mac)
        else:
            port = port.group()
        cdp_nei_ip = get_cdp_neighbor(core_conn, port)
        core_conn.disconnect()
        if cdp_nei_ip:
            cdp_nei_ip = cdp_nei_ip.group()
        else:
            cdp_nei_ip = None
        return match_mac, port, cdp_nei_ip
    else:
        return False


##########################################################################################################
#
#  trace_ip_address - Trace the MAC address through switches
#
##########################################################################################################
def trace_ip_address(ip):
    target_ip = str(ip)
    # check for reverse DNS entry
    dns_name = None
    try:
        dns_name = gethostbyaddr(target_ip)[0]
    except:
        pass
    if not dns_name:
        dns_name = "N/A"
    print("\nTracing " + target_ip + "...", end="")
    # obtain MAC, port, and check CDP for neighbor on core
    # if using cmd line arguments
    if options:
        mac, port, cdp_nei_ip = check_core(target_ip, options.core_switch, options.username, password, secret, options.vrf)
    # if using interactive prompts
    else:
        mac, port, cdp_nei_ip = check_core(target_ip, core_switch, username, password, secret, vrf)
    # move onto the next target if no ARP entry for current target
    if not mac:
        print("MAC not found in ARP")
        # line = "{},Not Found\n".format(target_ip)
        line = csv_line_template.format(target_ip, dns_name, "No ARP entry")
    elif cdp_nei_ip:
        # if using cmd line arguments
        if options:
            line = trace_mac(mac, target_ip, dns_name, cdp_nei_ip, options.username, password, secret)
        # if using interactive prompts
        else:
            line = trace_mac(mac, target_ip, dns_name, cdp_nei_ip, username, password, secret)
    else:
        print("MAC found on core, but no CDP neighbor detected.\n")
        line = csv_line_template.format(target_ip, dns_name, "No ARP entry",'',port)

    return line


##########################################################################################################
#
#  Main function
#
##########################################################################################################

def main():
    # if using script arguments
    if options:
        # if outputting to csv with arguments
        if options.filename:
            # Open the CSV and print the header
            csv_file = open(options.filename, "w")
            csv_file.write(csv_header)
            for ip in ipaddress.IPv4Network(options.network_to_scan):
                line = trace_ip_address(ip)
                print(line)
                csv_file.write(line)
    # if outputting to csv with prompts
    elif filename:
        csv_file = open(filename, "w")
        csv_file.write(csv_header)
        # Loop over each IP in the network and trace
        for ip in ipaddress.IPv4Network(network_to_scan):
            line = trace_ip_address(ip)
            print(csv_header + line)
            csv_file.write(line)
    # just print lines if not outputting to csv
    else:
        for ip in ipaddress.IPv4Network(network_to_scan):
            line = trace_ip_address(ip)
            print(csv_header + line)


main()
