import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from pwn import *
from termcolor import *


def direnum():
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

direnum()

