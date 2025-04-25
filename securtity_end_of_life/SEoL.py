from os import system as cmd
import os
import time
start = time.time()

access_key = os.environ['access_key'] # str(sys.argv[1])
secret_key = os.environ['secret_key'] # str(sys.argv[2])

url = "https://cloud.tenable.com"

# Replace 'access_key and secret_key with your keys
cmd('navi config keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi config update full')


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-SS-Scan_tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# Tag assets based on Unsupported software

cmd('navi enrich tag --c "End of Life" --v "Unsupported" --name "Unsupported"')

# Tag assets based on Security End of Life

cmd('navi enrich tag --c "End of Life" --v "Security End of Life" --name "SEoL"')


finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


