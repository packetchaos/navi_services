from os import system as cmd
import subprocess
import os
import time
from tenable.io import TenableIO
start = time.time()

access_key = os.environ['access_key'] # str(sys.argv[1])
secret_key = os.environ['secret_key'] # str(sys.argv[2])

url = "https://cloud.tenable.com"

tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Agent Group Tags - 0.0.1")

# Replace 'access_key and secret_key with your keys
cmd('navi config keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi config update full')


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-Agent-Group-tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# Grab all of the ports found open in the navi db
open_ports = subprocess.check_output('navi explore data query "select distinct port from vulns;"', shell=True)
list_of_ports = open_ports.decode('utf-8')

# Tag by port
for port in eval(list_of_ports):
    if port[0] != '0':
        cmd('navi enrich tag --c "Open Port" --v "Port: {}" --port {}'.format(port[0], port[0]))

finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


