import paramiko
import time
import re
import getpass

#Define global regexes
ip_regex=re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
subnet_regex=re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.')
mac_regex=re.compile(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}')
int_regex=re.compile(r'Fa{1}\d/\S*\d{1,2}|Gi{1}\d/\S*\d{1,2}|Eth{1}\d/\S*\d{1,2}')
int_po_regex=re.compile(r'Po{1}\d*')
int_regexes=[int_regex,int_po_regex]

#determine if single IP or range
target_type=input("Do you want to scan a single IP or a range?\n\n1. Single IP\n\n2. Range (must be contiguous; no greater than /24)\n\nPlease input 1 or 2: ")
while target_type != "1" and target_type != "2":
	target_type=input("\n\n1. Single IP\n\n2. Range (must be contiguous)\n\nPlease input 1 or 2: ")


if target_type == "1":
	startip="1"
	endip="1"
	current_ip=input("Enter IP address to trace: ")
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
		core_router_ssh = paramiko.SSHClient()
		core_router_ssh
		core_router_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		core_router_ssh.connect(core_router, username=username, password=password, look_for_keys=False, allow_agent=False)
		core_router_conn = core_router_ssh.invoke_shell()
		#obtain hostname of core device
		core_router_hostname=core_router_conn.recv(20)
		core_router_hostname=core_router_hostname.decode('utf-8')
		core_router_hostname=core_router_hostname.strip('\r\n')
		core_router_hostname=core_router_hostname.rstrip('#')
		core_router_conn.send("term len 0\n")
		time.sleep(.5)
		#ping IP to scan and obtain MAC
		core_router_conn.send("ping "+current_ip+" rep 2\n")
		time.sleep(.5)		
		core_router_conn.send("show ip arp "+current_ip+" | inc "+current_ip+"\n")
		time.sleep(.5)
		show_ip_arp=core_router_conn.recv(1000)
		show_ip_arp=show_ip_arp.decode(encoding='utf-8')
		match_mac=re.search(mac_regex,show_ip_arp)
		#end script if no MAC address found for given IP
		if not match_mac:
			core_router_ssh.close()
			print ("\nNo MAC for "+current_ip)
			cdp_nei_ip='1'
			match_mac='1'
			return (cdp_nei_ip,match_mac)
			break
		else:
			match_mac=match_mac.group()
			#obtain interface name that MAC was learned on from core device
			core_router_conn.send("show mac add add "+match_mac+" | inc "+match_mac+"\n")
			time.sleep(.5)
			show_mac_table=core_router_conn.recv(1000)
			show_mac_table=show_mac_table.decode(encoding='utf-8')
			#show_mac_table.replace('\\r\\n','\\n')
			#search for non-etherchannel interface name
			mac_port=re.search(int_regexes[0],show_mac_table)
			#if interface is an etherchannel, obtain member ports
			if not mac_port:			
				mac_port=re.search(int_regexes[1],show_mac_table)
				mac_port=mac_port.group()
				core_router_conn.send("show etherchan summ | inc "+mac_port+"\n")
				time.sleep(.5)
				etherchan_output=core_router_conn.recv(1000)
				etherchan_output=etherchan_output.decode(encoding='utf-8')
				mac_port=re.search(int_regexes[0],etherchan_output)
			mac_port=mac_port.group()
			core_router_conn.send("show cdp nei "+mac_port+" det | inc IP\n")
			time.sleep(.5)
			show_cdp_nei=core_router_conn.recv(120)				
			show_cdp_nei=show_cdp_nei.decode(encoding='utf-8')
			cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
			#if CDP neighbor is not found, check number of MACs learned on port
			if not cdp_nei_ip:
				core_router_conn.send("show mac add int "+mac_port+"\n")
				time.sleep(.5)
				mac_port_macs=core_router_conn.recv(1000)
				mac_port_macs=mac_port_macs.decode(encoding='utf-8')
				multi_macs=re.findall(mac_regex,mac_port_macs)
				core_router_ssh.close()
				#if more than one MAC is found on port, alert possible unmanaged switch
				if len(multi_macs) > 1:
					print ("\nNote: More than one MAC found on this port, possible unmanaged switch present.\n\n"+current_ip+','+match_mac+','+core_router_hostname+','+mac_port)
					match_mac='1'
					cdp_nei_ip='1'
					return(cdp_nei_ip,match_mac)
					break
				else:
					print ("\n"+current_ip+','+match_mac+','+core_router_hostname+','+mac_port)
					match_mac='1'
					cdp_nei_ip='1'
					return(cdp_nei_ip,match_mac)
					break
			else:
				core_router_ssh.close()
				cdp_nei_ip=cdp_nei_ip.group()
				#if CDP neighbor is found, see if IP provided is the CDP neighbor and alert
				if current_ip==cdp_nei_ip:
					print("\nNote: The IP provided is a CDP neighbor.\n\n"+current_ip+','+match_mac+','+core_router_hostname+','+mac_port)
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
		next_switch_ssh=paramiko.SSHClient()
		next_switch_ssh
		next_switch_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		next_switch_ssh.connect(cdp_nei_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
		next_switch_conn=next_switch_ssh.invoke_shell()				
		next_switch_hostname=next_switch_conn.recv(120)
		next_switch_hostname=next_switch_hostname.decode('utf-8')
		next_switch_hostname=next_switch_hostname.strip('\r\n')
		next_switch_hostname=next_switch_hostname.rstrip('#')
		next_switch_conn.send("show mac add add "+match_mac+" | inc "+match_mac+"\n")
		time.sleep(.5)
		show_mac_table=next_switch_conn.recv(1200)
		show_mac_table=show_mac_table.decode(encoding='utf-8')
		mac_port=re.search(int_regexes[0],show_mac_table)
		if not mac_port:
			mac_port=re.search(int_regexes[1],show_mac_table)
			mac_port=mac_port.group()
			next_switch_conn.send("show etherchan summ | inc "+mac_port+"\n")
			time.sleep(.5)					
			etherchan_output=next_switch_conn.recv(1000)
			etherchan_output=etherchan_output.decode(encoding='utf-8')
			mac_port=re.search(int_regexes[0],etherchan_output)
		mac_port=mac_port.group()
		next_switch_conn.send("show cdp nei "+mac_port+" det | inc IP\n")
		time.sleep(.5)
		show_cdp_nei=next_switch_conn.recv(120)
		show_cdp_nei=show_cdp_nei.decode(encoding='utf-8')
		cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
		if not cdp_nei_ip:
			next_switch_conn.send("show mac add int "+mac_port+"\n")
			time.sleep(.5)
			mac_port_macs=next_switch_conn.recv(1000)
			mac_port_macs=mac_port_macs.decode(encoding='utf-8')
			next_switch_ssh.close()
			multi_macs=re.findall(mac_regex,mac_port_macs)
			#if more than one MAC is found on port, alert possible unmanaged switch
			if len(multi_macs) > 1:
				print ("\nNote: More than one MAC found on this port, possible unmanaged switch present.\n\n"+current_ip+','+match_mac+','+next_switch_hostname+','+mac_port)
				cdp_nei_ip='1'
				no_cdp_nei_ip='1'
				return(cdp_nei_ip,no_cdp_nei_ip)
				break
			else:
				print ("\n"+current_ip+','+match_mac+','+next_switch_hostname+','+mac_port)
				cdp_nei_ip='1'
				no_cdp_nei_ip='1'
				return(cdp_nei_ip,no_cdp_nei_ip)
				break
		else:
			next_switch_ssh.close()
			cdp_nei_ip=cdp_nei_ip.group()
			#if CDP neighbor is found, see if IP provided is the CDP neighbor and alert
			if current_ip==cdp_nei_ip:
				print("\nNote: The IP provided is a CDP neighbor.\n\n"+current_ip+','+match_mac+','+next_switch_hostname+','+mac_port)
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