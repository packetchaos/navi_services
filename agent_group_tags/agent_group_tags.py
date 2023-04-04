from os import system as cmd
import sys
import time
from tenable.io import TenableIO
start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])

url = "https://cloud.tenable.com"

tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Agent Group Tags - 0.0.1")

# Replace 'access_key and secret_key with your keys
cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi update full')


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-Agent-Group-tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# Get Agent Groups using pytenable
agent_raw_data = tio.agent_groups.list(scanner_id=0)

# Cycle through each scan and tag each one by Scan ID
for groups in agent_raw_data:
    group_name = groups['name']

    print("Tagging assets in Agent Group: {}\n".format(group_name))

    # Use Navi to tag Assets by Agent group
    cmd('navi tag --c "Agent Group" --v "{}" --group "{}"'.format(group_name, group_name))


finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


