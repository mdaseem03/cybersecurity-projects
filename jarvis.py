#! /usr/bin/python3
#python3 jarvis.py
import time
import whois  
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from pwn import *
from termcolor import *
import nmap
import socket
import hashlib


def intro():
    print("\033[1;33m")  # set text color to yellow
    text = '''                                                    
                     _____    ____ ______
          / /   |  / __ \ |  / /  _/ ___/
     __  / / /| | / /_/ / | / // / \__ \ 
    / /_/ / ___ |/ _, _/| |/ // / ___/ / 
    \____/_/  |_/_/ |_| |___/___//____/  v0.1 
                                             '''
    for line in text.split('\n'):
        print(line)
        time.sleep(0.5)  
    time.sleep(0.5)
    print("\u001b[36m") #set color to cyan
    print("\n\t\tAuthor: mdaseem_03")

def display_message():
    print("\u001b[0m") # reset color
    print("-"*60)
    print("\u001b[33m") #yellow color
    print("#"*60)
    print(" \t\tRECONNAISANCE AND SCANNING ")
    print("#"*60)
    print("[1] WHOIS Lookup")
    print("[2] Directory Enumeration")
    print("[3] Subdomain Enumeration")
    print("[4] Port Scanning")
    print("\n")
    print("#"*60)
    print(" \t\t\tEXPLOITATION ")
    print("#"*60)
    print("[5] SHA256 Cracker")
    print("\n")
    print("\n")
    print("[0] Exit")
    
def whois_lookup():
    print("\033[1;37m") #bold white    
    print("#"*60)
    print(" \t\t\tWHOIS LOOKUP ")
    print("#"*60)

    print("\u001b[0m")#reset color
    domain = input(">> Enter Domain Name: ")
    print("\n")
    print("-"*60)
    print(domain)
    
    w = whois.whois(domain)
    print("Domain Name: {}".format(w.domain_name))
    print("Registrar: {}".format(w.registrar))
    print("Creation Date: {}".format(w.creation_date))
    print("Expiration Date: {}".format(w.expiration_date))
    print("Last Updated Date: {}".format(w.last_updated))
    print("Name Servers: {}".format(w.name_servers))
    print("Registrant Name: {}".format(w.name))
    print("Registrant Organization: {}".format(w.org))
    print("Registrant Email: {}".format(w.email))
    print("Registrant Phone: {}".format(w.phone))
    print("Registrant Address: {}".format(w.address))
    print("Registrant City: {}".format(w.city))
    print("Registrant State/Province: {}".format(w.state))
    print("Registrant Postal Code: {}".format(w.zipcode))
    print("Registrant Country: {}".format(w.country))

def direnum():
    print("\033[1;37m") #bold white    
    print("#"*60)
    print(" \t\t\tDIRECTORY ENUMERATION ")
    print("#"*60)
    print("\u001b[0m")

    url = input(">> Enter URL: ").strip()
    dir_list = input(">> Enter Wordlist: ").strip()
    concurrent = 50

    def check_directory(directory):
        directory = directory.strip()  # remove any whitespace
        full_url = url + "/" + directory
        response = requests.get(full_url)
        status_code = response.status_code
        if status_code != 404:
            if 300 <= status_code < 400:
                print(colored("{} : Status Code [{}]".format(full_url,status_code), 'orange'))
            elif status_code == 200:
                print(colored("{} : Status Code [{}]".format(full_url,status_code), 'green'))
            elif 400 <= status_code < 500 and status_code != 404:
                print(colored("{} : Status Code [{}]".format(full_url,status_code), 'yellow'))
            else:
                print(colored("{} : Status Code [{}]".format(full_url,status_code), 'red'))

    with log.progress("Bruteforcing directories at {} \n".format(url)) as p:
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = [executor.submit(check_directory, directory) for directory in open(dir_list)]
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                sys.exit(1)
        p.success("Directories Enumeration Completed")


def subdomain_enum():
    print("\033[1;37m") #bold white    
    print("#"*60)
    print(" \t\t\tSUBDOMAIN ENUMERATION ")
    print("#"*60)
    print("\u001b[0m")

    domain = input(">> Enter Domain: ").strip()
    wordlist = input(">> Enter Wordlist: ").strip()
    print('\n')
    
    sub = open(wordlist,'r')
    
    with log.progress("Enumerating subdomains for {} \n".format(domain)) as p:
        def enum(subdomain):
            global count
            count = 0 #used to print final success or failure message
            subdomain = subdomain.strip() # remove whitespace and newline characters
            url = "{}.{}".format(subdomain,domain)

            try:
                ip = socket.gethostbyname(url)
            except Exception:
                pass
            else:
                print("[*] {} [{}]".format(url,ip))
                count += 1

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(enum, subdomain) for subdomain in sub]
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                p.status("Received KeyboardInterrupt. Stopping threads...")
                executor.shutdown(wait=False)
            if count!=0:
                p.success("Subdomains found: ")
            else:
                p.failure("Finished !!")

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

def portscan():
    global nm
    nm = nmap.PortScanner()
    ip = input(">> Enter [IP Address|Domain|URL]: ")
    ports = input(">> Enter Ports Range: ")

    try:
        url = ip
        domain = whois.whois(url).domain_name
        ip = socket.gethostbyname(domain)
    except TypeError:
        ip = ip
        
    print("-"*20)
    print("IP Address: ",ip)
    print("Port Range: ",ports)
    print("-"*20)

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

def shacrack():
    wanted_hash = input(">> Enter Hash Value: ").strip()#sha256sum is stored
    password_file = input(">> Enter Wordlist: ").strip() #reads password file path
    attempts = 0 #it will calc n.o. of attempts

    with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p: #for displaying progress of execution
        with open(password_file, "r", encoding='utf-8') as password_list: #open password file(rockyou.txt) with enc=utf-8. Because for hashing, string should be encoded
            for password in password_list: #iterates each line in password file
                password = password.strip("\n").encode('utf-8') #password is encoded to utf-8
                password_obj = hashlib.sha256(password) #password is converted to sha256
                password_hash = password_obj.hexdigest()
                p.status("[{}] {} == {}".format(attempts, password.decode('utf-8'), password_hash)) #display status of execution in each iteration
                if password_hash == wanted_hash:
                    p.success("Password Hash found after {} attempts! \033[1m\033[92m{}\033[0m hashes to {}!".format(attempts, password.decode('utf-8'), password_hash))
                    exit()
                attempts +=1
            p.failure("Password Hash not found !")





if __name__ == "__main__":
    intro()
    display_message()
    print("\u001b[0m")

    def choice():
        global ch 
        try:
            ch=int(input("jarvis >"))
        except:
            print("Enter correct choice: ")
            choice()
    choice()

    if ch == 1:
        whois_lookup()
    elif ch == 2:
        direnum()
    elif ch == 3:
        subdomain_enum()
    elif ch == 4:
        portscan()
    elif ch == 5:
        shacrack()
    elif ch == 0:
        print("See You Again Chief !! ...")
        sys.exit(1)


