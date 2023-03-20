#! /usr/bin/python3
#python3 jarvis.py
import time
import whois
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from pwn import *


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
    print("[5] Full Reconnaisance and Scanning")
    print("\n")
    print("#"*60)
    print(" \t\t\tEXPLOITATION ")
    print("#"*60)
    print("[6] SHA256 Cracker")
    print("\n")
    
def whois_lookup():
    print("\033[1;37m") #bold white    
    print("#"*60)
    print(" \t\t\tWHOIS LOOKUP ")
    print("#"*60)

    print("\u001b[0m")#reset color
    domain = input(">> Enter Domain Name: ")
    print("\n")
    print("-"*60)
    
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

    url = input(">> Enter URL: ")
    dir_list = input(">> Enter Wordlist: ").split('\n')
    concurrent = 50

    def check_directory(directory):
        directory = directory.strip()  # remove any whitespace
        full_url = url + directory
        response = requests.get(full_url)
        if response.status_code != 404:
            print("{} : Status Code [{}]".format(full_url,response.status_code))

    with log.progress("Bruteforcing directories at {} \n".format(url)) as p:
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = [executor.submit(check_directory, directory) for directory in open(dir_list)]
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                p.status("Received KeyboardInterrupt. Stopping threads...")
                executor.shutdown(wait=False)
        p.success("Directories Enumeration Completed")



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



