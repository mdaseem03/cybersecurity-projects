import sys 
import requests
from pwn import *
from concurrent.futures import ThreadPoolExecutor
import socket

# python3 -h
#python3 filename.py -d <domain name> -w <wordlist>

if len(sys.argv) == 2 and sys.argv[1] == "-h": #print HELP 
    print("Syntax: python3 {} -d <domain name> -w <wordlist>".format(sys.argv[0]))
elif len(sys.argv) == 5 and sys.argv[1] == "-d" and sys.argv[3] == "-w": #enumerate subdomains
    wordlist = sys.argv[4]
    domain = sys.argv[2]
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
else:
    print("For Help: python3 {} -h".format(sys.argv[0]))

