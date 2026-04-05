import jwt 
import subprocess
import argparse
import re
import requests

# Colors 
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"
jwtRegex = r"\*ey.*?\*"


def displayHeader(header):
    print(f"{'Key':<10} | {'Value':<10}")
    print('-'*23)

    for k,v in header.items():
        print(f"{YELLOW}{k:<10}{RESET} | {GREEN}{v:<10}{RESET}")


def bruteforce(token, algorithm):

    if algorithm == 'None':
        pass 

    elif algorithm == 'HS256':
        # Bruteforce HS256 
        cmd = [
            "hashcat",
            "-a", "0",
            "-m", "16500",
            token,
            "--quite",
            "./jwtCommanlist/jwtFuzz.txt"
        ]


        try: 
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(token)
            print(result.stdout)
        
        except Exception as e:
            print(f"{RED}[-] Error during bruteforce: {e}{RESET}")
    else : 
        print('algorithm miss match')

## Get request from  files 
def getRequestFromFile(httpRequestFile):
    with open(f'{httpRequestFile}', 'r') as f:
        content = f.read()   
        return content     


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
    response = requests.request(method=method, url=url, headers=headers, data=body)

    print(response.status_code)


def noneAlgattack(token):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--bruteforce", help="Initiate the bruteforce process", action="store_true")
    parser.add_argument("-t","--token", help="JWT token argument", type=str, required=False, default='eyJhbGciOiJub25lIiwiZm9vbCI6ImZvb2wifQ.eyJmb29sIjoidHJ1ZSJ9.')
    parser.add_argument("-f", "--file", help="RAW HTTP request file ; TOken should be surounded by *ey........*")

    args = parser.parse_args()

    token = args.token 
    rawFileHttp = args.file

    header = jwt.get_unverified_header(token)

    algorithm = header.get('alg')

    
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

    else:
        displayHeader(header)



    if args.bruteforce:
        bruteforce(token, algorithm)



if __name__ == "__main__" : 
    main()

