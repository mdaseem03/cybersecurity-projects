import os
import subprocess
import requests
import argparse

# Function to replace FUZZ with payloads and test for XSS
def test_xss(output_file, payloads_file):
    with open(output_file, 'r') as file:
        lines = file.readlines()

    payloads = []
    with open(payloads_file, 'r') as file:
        payloads = [line.strip() for line in file]

    for line in lines:
        url = line.strip()
        for payload in payloads:
            # Replace FUZZ with payload
            test_url = url.replace("FUZZ", payload)

            try:
                # Send a GET request and store response
                response = requests.get(test_url)

                # Check if the payload is reflected in the response
                if payload in response.text:
                    print(f"[+] Potential XSS Found in: {test_url}")
                    print(f"    Payload: {payload}")
            except Exception as e:
                pass  # Ignore errors

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-p", "--payloads-file", required=True, help="Path to the payloads file")
    args = parser.parse_args()

    print('''
          --------------------------------------
          |                                     |
          |              XSS-SCANNER            |
          |           Author: mdaseem03         |
          |                                     |
          |                                     |  
          ---------------------------------------
          ''')
    domain = args.domain
    output_file = f"output-{domain}-param.txt"
    payloads_file = args.payloads_file

    # Run ParamSpider and capture the output in a file
    paramspider_cmd = f"paramspider -d {domain} > {output_file}"
    subprocess.run(paramspider_cmd, shell=True, check=True)

    print("Testing for XSS vulnerabilities...")
    test_xss(output_file, payloads_file)
