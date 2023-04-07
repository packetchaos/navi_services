from os import system as cmd
import sys
import time
import requests
from tenable.io import TenableIO
import subprocess

start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])

url = "https://cloud.tenable.com"

cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi update full')


tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Agent Group Tags - 0.0.1")


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-SS-Scan_tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# Tag assets based on 19506 Data
cmd('navi tag --c "Scan Time" --v "Over 20 Mins" --scantime 20')
cmd('navi tag --c "Scan Time" --v "Over 30 Mins" --scantime 30')
cmd('navi tag --c "Scan Time" --v "Over 60 Mins" --scantime 60')
cmd('navi tag --c "Scan Time" --v "Over 90 Mins" --scantime 90')

# Credential issues
cmd('navi tag --c "Credential Issues" --v "Credential Failure" --plugin 104410')
cmd('navi tag --c "Credential Issues" --v "General Failure" --plugin 21745')
cmd('navi tag --c "Credential Issues" --v "Insufficient Privilege" --plugin 110385')
cmd('navi tag --c "Credential Issues" --v "Intermittent Auth Failure" --plugin 117885')

# Tags on CISA Known Vulns
cmd('navi tag --c "CISA" --v "Known Vulns" --xrefs CISA')

# Docker hosts
cmd('navi tag --c "Docker" --v "Host" --plugin 93561')

# VMware Hosts
cmd('navi tag --c "VMWare" --v "Host" --plugin 20301')
cmd('navi tag --c "VMWare" --v "Virtual Machine" --plugin 20094')

# Website found
cmd('navi tag --c "Web Applications" --v "HTTP information Found" --plugin 24260')

# Requires a reboot
cmd('navi tag --c "Reboot" --v "Required" --plugin 35453')
cmd('navi tag --c "Reboot" --v "Required" --plugin 163103')

# Certificate Issues
cmd('navi tag --c "SSL Certificates" --v "SSL Detection" --plugin 10863')
cmd('navi tag --c "Certificate Issues" --v "SSL Cert Expired!" --plugin 15901')
cmd('navi tag --c "Certificate Issues" --v "Less than 2048 bits!" --plugin 69551')
cmd('navi tag --c "Certificate Issues" --v "Not Trusted!" --plugin 51192')
cmd('navi tag --c "Certificate Issues" --v "SSL Cert Expires Soon!" --plugin 42981')
cmd('navi tag --c "Certificate Issues" --v "Weak Keys!" --plugin 60108')

# Scan ID tags
raw_scan_id_data = requests.request('GET', url + '/scans', headers=grab_headers()).json()

# Cycle through each scan and tag each one by Scan ID
for scans in raw_scan_id_data['scans']:
    if scans['status'] == 'completed':
        if not scans['is_archived']:
            scanid = scans['id']
            print("Tagging assets scanned by Scan ID {}\n".format(scanid))
            cmd('navi tag --c "Scan ID" --v "{}" --scanid {}'.format(scanid, scanid))


# Get Agent Groups using pytenable
agent_raw_data = tio.agent_groups.list(scanner_id=0)

# Cycle through each scan and tag each one by Scan ID
for groups in agent_raw_data:
    group_name = groups['name']

    print("Tagging assets in Agent Group: {}\n".format(group_name))

    # Use Navi to tag Assets by Agent group
    cmd('navi tag --c "Agent Group" --v "{}" --group "{}"'.format(group_name, group_name))

# Grab all of the ports found open in the navi db
open_ports = subprocess.check_output('navi find query "select distinct port from vulns;"', shell=True)
list_of_ports = open_ports.decode('utf-8')

# Tag by port
for port in eval(list_of_ports):
    if port[0] != '0':
        cmd('navi tag --c "Open Port" --v "Port: {}" --port {}'.format(port[0], port[0]))

finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


