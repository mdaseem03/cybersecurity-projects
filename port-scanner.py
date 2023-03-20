import nmap 
import sys 
import socket
import whois
import threading

# python3 port-scanner.py <ipadd|domain|url> 
# python3 port-scanner.py <ipadd|domain|url> -p <range>
# python3 port-scanner.py <ipadd|domain|url> -p all
# python3 port-scanner.py -h 

nm = nmap.PortScanner()
def argcheck():
	global ports 
	if len(sys.argv) == 2 and sys.argv[1] == '-h':
		print("Syntax: python3 {} <ipaddress|domain|url> -p <range>".format(sys.argv[0]))
		print("If port is not specified, by default first 1000 ports is scanned")
		print("To scan all ports, Syntax: python3 {} <ipaddress|domain|url> -p all ".format(sys.argv[0]))
		sys.exit(1)
	elif len(sys.argv) == 2 and sys.argv[1] != 'h':
		ports = '1-1000'
	elif len(sys.argv) == 4 and sys.argv[3] == "all":
		ports = '1-65535'
	elif len(sys.argv) == 4 and sys.argv[3] != "all":
		ports = sys.argv[3]
	else:
		print("For Help: python3 {} -h".format(sys.argv[0]))
		sys.exit(1)
argcheck()

def scan_ports(ip, ports):
	nm.scan(ip, ports)
	for hosts in nm.all_hosts():
		for proto in nm[hosts].all_protocols():
			lport = nm[hosts][proto].keys()
			#lport.sorted()
			print("PORT\t\tSERVICE\t\tSTATE")
			print("----\t\t-------\t\t-----")
			for port in lport:
				try:
					service = socket.getservbyport(port)
				except Exception:
					service="unknown"
				print("{}/{}\t\t{}\t\t{}".format(port,proto,service,nm[hosts][proto][port]['state']))

try:
	url = sys.argv[1]
	domain = whois.whois(url).domain_name
	ip = socket.gethostbyname(domain)
except TypeError:
	ip = sys.argv[1]
	
print("#"*20)
print("IP Address: ",ip)
print("Ports: ",ports)
print("#"*20)

# Split the port range into chunks for threading
port_chunks = ports.split(",")
threads = []

for chunk in port_chunks:
	start_port, end_port = chunk.split("-")
	thread = threading.Thread(target=scan_ports, args=(ip, "{}-{}".format(start_port, end_port)))
	thread.start()
	threads.append(thread)

# Wait for all threads to finish
for thread in threads:
	thread.join()
