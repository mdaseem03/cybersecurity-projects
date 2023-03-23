import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from pwn import *
from termcolor import *


if len(sys.argv) != 5:
    print('Usage: python3 hiddir.py -u <url> -d <dir wordlist>')
    sys.exit(1)

url = sys.argv[2]
dir_list = sys.argv[4]
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
            p.status("Received KeyboardInterrupt. Stopping threads...")
            executor.shutdown(wait=False)
    p.success("Directories Enumeration Completed")
