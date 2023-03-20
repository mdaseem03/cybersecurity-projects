#SHA256 crack 

from pwn import *
import sys
import hashlib #importing libraries

#python3 sha256-crack.py -h
if len(sys.argv) == 2 and sys.argv[1] == "-h": #length of cmd == 2 and 2nd word is -h. It will display help message
    print(""" SHA256-Crack by Mohammed Aseem - Please do not use for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway)\n""")
    print("Syntax: python3 {} <sha256sum> [-w WORDLIST]".format(sys.argv[0]))

#python3 sha256-crack.py <sha256sum> -w /usr/share/wordlists/rockyou.txt
elif len(sys.argv) == 4 and sys.argv[2] == "-w": #length of cmd == 4 
    wanted_hash = sys.argv[1] #sha256sum is stored
    password_file = sys.argv[3] #reads password file path
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
elif len(sys.argv) != 2 and len(sys.argv) != 4: #Checks if there are two arguements or 4 arguements to see whether user used correct syntax
    print("Invalid Arguements !")
    print(">> python3 {} -h for help".format(sys.argv[0]))