from os import system as cmd
import sys
import time
import requests
start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])

url = "https://cloud.tenable.com"

# Replace 'access_key and secret_key with your keys
cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi update full')


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


# Scan ID tags
raw_scan_id_data = requests.request('GET', url + '/scans', headers=grab_headers()).json()

# Cycle through each scan and tag each one by Scan ID
try:
    for scans in raw_scan_id_data['scans']:
        if scans['status'] == 'completed':
            if not scans['is_archived']:
                scanid = scans['id']
                print("Tagging assets scanned by Scan ID {}\n".format(scanid))
                cmd('navi tag --c "Scan ID" --v "{}" --scanid {}'.format(scanid, scanid))
except KeyError:
    pass



finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


