import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from pwn import *



if len(sys.argv) != 5:
    print('Usage: python3 hiddir.py -u <url> -d <dir wordlist>')
    sys.exit(1)

url = sys.argv[2]
dir_list = sys.argv[4]
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
