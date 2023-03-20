import whois
import sys 
from pwn import *

# python3 info.py -h
# python3 info.py -d <domain name>


if len(sys.argv)==2 and sys.argv[1] == '-h':
    print(">> python3 {} -d <domain name>\n".format(sys.argv[0]))
elif len(sys.argv) == 3 and sys.argv[1] == '-d': 
    def get_whois_info(domain):
        # Retrieve WHOIS information for the specified domain
        w = whois.whois(domain)
        # Print out the WHOIS information
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
        

    domain = sys.argv[2]
    get_whois_info(domain)
else:
    print(">> python3 {} -h : for help\n".format(sys.argv[0]))



