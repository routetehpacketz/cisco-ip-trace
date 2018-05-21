import paramiko
import time
import re
import getpass
import datetime

#Define global regexes
ip_regex=re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
mac_regex=re.compile(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}')
int_regex=re.compile(r'Fa{1}\d/\S*\d{1,2}|Gi{1}\d/\S*\d{1,2}|Eth{1}\d/\S*\d{1,2}')
int_po_regex=re.compile(r'Po{1}\d*')
int_regexes=[int_regex,int_po_regex]

#get core device IP and IP to trace
core_router=input("Enter the IP address of the core router/switch that can ARP for the IP address to trace: ")
while not re.match(ip_regex,core_router):
	core_router=input("The entered value is not an IP address. Please re-enter the IP of the core router/swotch: ")

current_ip=input("Enter IP address to trace: ")
while not re.match(ip_regex,current_ip):
	current_ip=input("Enter a valid IP address to trace: ")	

#get creds for logging into Cisco gear via SSH
username=input("Username: ")
password=getpass.getpass()

def main():
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
	time.sleep(1)
	#ping IP to scan and obtain MAC
	core_router_conn.send("ping "+current_ip+" rep 2\n")
	time.sleep(1)		
	core_router_conn.send("show ip arp "+current_ip+" | inc "+current_ip+"\n")
	time.sleep(1)
	show_ip_arp=core_router_conn.recv(1000)
	show_ip_arp=show_ip_arp.decode(encoding='utf-8')
	match_mac=re.search(mac_regex,show_ip_arp)
	#end script if no MAC address found for given IP
	if not match_mac:
		print ("No MAC for "+current_ip)
	else:
		match_mac=match_mac.group()
		#obtain interface name that MAC was learned on from core device
		core_router_conn.send("show mac add add "+match_mac+" | inc "+match_mac+"\n")
		time.sleep(1)
		show_mac_table=core_router_conn.recv(1000)
		show_mac_table=show_mac_table.decode(encoding='utf-8')
		show_mac_table.replace('\\r\\n','\\n')
		#search for non-etherchannel interface name
		mac_port=re.search(int_regexes[0],show_mac_table)
		#if interface is an etherchannel, obtain member ports
		if not mac_port:			
			mac_port=re.search(int_regexes[1],show_mac_table)
			mac_port=mac_port.group()
			core_router_conn.send("show etherchan summ | inc "+mac_port+"\n")
			time.sleep(1)
			etherchan_output=core_router_conn.recv(1000)
			etherchan_output=etherchan_output.decode(encoding='utf-8')
			mac_port=re.search(int_regexes[0],etherchan_output)
		mac_port=mac_port.group()
		core_router_conn.send("show cdp nei "+mac_port+" det | inc IP\n")
		time.sleep(1)
		show_cdp_nei=core_router_conn.recv(120)				
		show_cdp_nei=show_cdp_nei.decode(encoding='utf-8')
		cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
		if not cdp_nei_ip:
			print (current_ip+','+match_mac+','+core_router_hostname+','+mac_port)
		else:
			def check_cdp_nei():
				nonlocal cdp_nei_ip
				next_switch_ssh=paramiko.SSHClient()
				next_switch_ssh
				next_switch_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				next_switch_ssh.connect(cdp_nei_ip.group(), username=username, password=password, look_for_keys=False, allow_agent=False)
				next_switch_conn=next_switch_ssh.invoke_shell()				
				next_switch_hostname=next_switch_conn.recv(12)
				next_switch_hostname=next_switch_hostname.decode('utf-8')
				next_switch_hostname=next_switch_hostname.strip('\r\n')
				next_switch_hostname=next_switch_hostname.rstrip('#')
				next_switch_conn.send("show mac add add "+match_mac+" | inc "+match_mac+"\n")
				time.sleep(1)
				show_mac_table=next_switch_conn.recv(120)
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
				next_switch_conn.send("show cdp nei "+mac_port.group()+" det | inc IP\n")
				time.sleep(1)
				show_cdp_nei=next_switch_conn.recv(120)
				next_switch_ssh.close()
				show_cdp_nei=show_cdp_nei.decode(encoding='utf-8')
				cdp_nei_ip=re.search(ip_regex,show_cdp_nei)
				if not cdp_nei_ip:
					print('\n'+current_ip+','+match_mac+','+next_switch_hostname+','+mac_port.group())
					next_switch_ssh.close()
				else:
					check_cdp_nei()
			check_cdp_nei()
main()