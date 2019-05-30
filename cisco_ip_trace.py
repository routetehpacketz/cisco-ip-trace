from netmiko import ConnectHandler
import time
import re
import getpass

#Define global regexes
ip_regex=re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
subnet_regex=re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.')
mac_regex=re.compile(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}')
int_regex=re.compile(r'Fa{1}\S*\d/\S*\d{1,2}|Gi{1}\S*\d/\S*\d|Eth{1}\d/\S*\d{1,2}')
int_po_regex=re.compile(r'Po{1}\d*')
int_regexes=[int_regex,int_po_regex]

#determine if single IP or range
target_type=input("Do you want to scan a single IP or a range?\n\n1. Single IP\n2. Range (must be contiguous; no greater than /24)\n\nSelect 1 or 2: ")
while target_type != "1" and target_type != "2":
	target_type=input("\n\n1. Single IP\n\n2. Range (must be contiguous)\n\nPlease input 1 or 2: ")

if target_type == "1":
	startip="1"
	endip="1"
	current_ip=input("Enter IP address to trace: ")
	current_vrf=input("Enter VRF for the IP: ")
	while not re.match(ip_regex,current_ip):
		current_ip=input("Enter a valid IP address to trace: ")
else:
	subnet=input("Enter first three octets of subnet you'd like to scan (ex. 10.1.1.): ")
	while not re.match(subnet_regex,subnet):
		subnet=input("Enter first three octets of subnet you'd like to scan (ex. 10.1.1.): ")
	startip=input("Enter last octet of first IP in the range to scan: ")
	while int(startip) not in range(1,255):
		startip=input("Enter a number between 1 and 254: ")
	endip=input("Enter the last octet of the last IP in the range to scan: ")
	while int(endip) not in range(1,255) or int(endip)<int(startip):
		endip=input("Enter a number between "+str(int(startip)+1)+" and 254: ")

core_router=input("Enter the IP address of the core router/switch that can ARP for the IP address to trace: ")
while not re.match(ip_regex,core_router):
	core_router=input("The entered value is not an IP address. Please re-enter the IP of the core router/switch: ")

#get creds for logging into Cisco gear via SSH
username=input("Username: ")
password=getpass.getpass()

def core(core_router,current_ip):
	while True:
		#connect to core device
		core_router_conn=ConnectHandler(device_type='cisco_ios',host=core_router,username=username,password=password)
		#obtain hostname of core device
		core_router_hostname=core_router_conn.find_prompt()
		#ping IP to scan and obtain MAC
		core_router_conn.send_command("ping vrf"+current_vrf+" "+current_ip+" rep 2\n",delay_factor=.1)
		show_ip_arp=core_router_conn.send_command("show ip arp vrf "+current_vrf+" "+current_ip+"\n",delay_factor=.1)
		match_mac=re.search(mac_regex,show_ip_arp)
		#end script if no MAC address found for given IP
		if not match_mac:
			core_router_conn.disconnect()
			print ("\nNo MAC for "+current_ip+"\n")
			cdp_nei_ip='1'
			match_mac='1'
			return (cdp_nei_ip,match_mac)
			break
		else:
			match_mac=match_mac.group()
			routed_port=re.search(int_regex,show_ip_arp)
			if routed_port:
				routed_port=routed_port.group()
				show_cdp_nei=core_router_conn.send_command("show cdp nei "+routed_port+" det | inc IP",delay_factor=.1)
				cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
				if not cdp_nei_ip:
					print ("\n"+current_ip+" is directly connected to the core router\n")
					cdp_nei_ip='1'
					match_mac='1'
					return (cdp_nei_ip,match_mac)
					break
				else:
					core_router_conn.disconnect()
					cdp_nei_ip=cdp_nei_ip.group()
					#if CDP neighbor is found, see if IP provided is the CDP neighbor and alert
					if current_ip==cdp_nei_ip:
						print("\nNote: The IP provided is a CDP neighbor.\n\n"+current_ip+','+match_mac+','+core_router_hostname.rstrip('#')+','+mac_port+"\n")
						match_mac='1'
						cdp_nei_ip='1'
						return(cdp_nei_ip,match_mac)
						break
					else:
					#if IP provided is not a CDP neighbor, return variables for use in check_cdp_nei function
						return (cdp_nei_ip,match_mac)
						break

			#obtain interface name that MAC was learned on from core device
			show_mac_table=core_router_conn.send_command("show mac add add "+match_mac+" | inc "+match_mac)
			#search for non-etherchannel interface name
			mac_port=re.search(int_regexes[0],show_mac_table)
			#if interface is an etherchannel, obtain member ports
			if not mac_port:
				mac_port=re.search(int_regexes[1],show_mac_table)
				mac_port=mac_port.group()
				etherchan_output=core_router_conn.send_command("show etherchan summ | inc "+mac_port,delay_factor=.1)
				mac_port=re.search(int_regexes[0],etherchan_output)
			mac_port=mac_port.group()
			show_cdp_nei=core_router_conn.send_command("show cdp nei "+mac_port+" det | inc IP",delay_factor=.1)
			cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
			#if CDP neighbor is not found, check number of MACs learned on port
			if not cdp_nei_ip:
				mac_port_macs=core_router_conn.send_command("show mac add int "+mac_port,delay_factor=.1)
				multi_macs=re.findall(mac_regex,mac_port_macs)
				core_router_conn.disconnect()
				#if more than one MAC is found on port, alert possible unmanaged switch
				if len(multi_macs) > 1:
					print ("\nNote: More than one MAC found on this port, possible unmanaged switch present.\n\n"+current_ip+','+match_mac+','+core_router_hostname.rstrip('#')+','+mac_port+"\n")
					match_mac='1'
					cdp_nei_ip='1'
					return(cdp_nei_ip,match_mac)
					break
				else:
					print ("\n"+current_ip+','+match_mac+','+core_router_hostname.rstrip('#')+','+mac_port+"\n")
					match_mac='1'
					cdp_nei_ip='1'
					return(cdp_nei_ip,match_mac)
					break
			else:
				core_router_conn.disconnect()
				cdp_nei_ip=cdp_nei_ip.group()
				#if CDP neighbor is found, see if IP provided is the CDP neighbor and alert
				if current_ip==cdp_nei_ip:
					print("\nNote: The IP provided is a CDP neighbor.\n\n"+current_ip+','+match_mac+','+core_router_hostname.rstrip('#')+','+mac_port+"\n")
					match_mac='1'
					cdp_nei_ip='1'
					return(cdp_nei_ip,match_mac)
					break
				else:
				#if IP provided is not a CDP neighbor, return variables for use in check_cdp_nei function
					return (cdp_nei_ip,match_mac)
					break

def check_cdp_nei(cdp_nei_ip,match_mac,current_ip):
	while True:
		next_switch_conn=ConnectHandler(device_type='cisco_ios',host=cdp_nei_ip,username=username,password=password)
		next_switch_hostname=next_switch_conn.find_prompt()
		show_mac_table=next_switch_conn.send_command("show mac add add "+match_mac+" | inc "+match_mac,delay_factor=.1)
		mac_port=re.search(int_regexes[0],show_mac_table)
		if not mac_port:
			mac_port=re.search(int_regexes[1],show_mac_table)
			mac_port=mac_port.group()
			etherchan_output=next_switch_conn.send_command("show etherchan summ | inc "+mac_port,delay_factor=.1)
			mac_port=re.search(int_regexes[0],etherchan_output)
		mac_port=mac_port.group()
		show_cdp_nei=next_switch_conn.send_command("show cdp nei "+mac_port+" det | inc IP",delay_factor=.1)
		cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
		if not cdp_nei_ip:
			mac_port_macs=next_switch_conn.send_command("show mac add int "+mac_port+"\n",delay_factor=.1)
			next_switch_conn.disconnect()
			multi_macs=re.findall(mac_regex,mac_port_macs)
			#if more than one MAC is found on port, alert possible unmanaged switch
			if len(multi_macs) > 1:
				print ("\nNote: More than one MAC found on this port, possible unmanaged switch present.\n\n"+current_ip+','+match_mac+','+next_switch_hostname.rstrip('#')+','+mac_port+"\n")
				cdp_nei_ip='1'
				no_cdp_nei_ip='1'
				return(cdp_nei_ip,no_cdp_nei_ip)
				break
			else:
				print ("\n"+current_ip+','+match_mac+','+next_switch_hostname.rstrip('#')+','+mac_port+"\n")
				cdp_nei_ip='1'
				no_cdp_nei_ip='1'
				return(cdp_nei_ip,no_cdp_nei_ip)
				break
		else:
			next_switch_conn.disconnect()
			cdp_nei_ip=cdp_nei_ip.group()
			#if CDP neighbor is found, see if IP provided is the CDP neighbor and alert
			if current_ip==cdp_nei_ip:
				print("\nNote: The IP provided is a CDP neighbor.\n\n"+current_ip+','+match_mac+','+next_switch_hostname.rstrip('#')+','+mac_port+"\n")
				cdp_nei_ip='1'
				no_cdp_nei_ip='1'
				return(cdp_nei_ip,no_cdp_nei_ip)
				break
			no_cdp_nei_ip='2'
			return(cdp_nei_ip,no_cdp_nei_ip)

def singleip_scan():
	no_cdp_nei_ip='2'
	cdp_nei_ip,match_mac=core(core_router,current_ip)
	if match_mac!='1':
		while no_cdp_nei_ip=='2':
			cdp_nei_ip,no_cdp_nei_ip=check_cdp_nei(cdp_nei_ip,match_mac,current_ip)

def range_scan():
	no_cdp_nei_ip='2'
	for i in range(int(startip),(int(endip)+1)):
		no_cdp_nei_ip='2'
		current_ip=subnet+str(i)
		cdp_nei_ip,match_mac=core(core_router,current_ip)
		if match_mac!='1':
			while no_cdp_nei_ip=='2':
				cdp_nei_ip,no_cdp_nei_ip=check_cdp_nei(cdp_nei_ip,match_mac,current_ip)

def main():
	if target_type=="1":
		singleip_scan()
	else:
		range_scan()

main()
