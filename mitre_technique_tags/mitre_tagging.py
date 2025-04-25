from os import system as cmd
import os
import time
import requests
import pandas as pd
import io

start = time.time()

access_key = os.environ['access_key'] # str(sys.argv[1])
secret_key = os.environ['secret_key'] # str(sys.argv[2])

url = "https://cloud.tenable.com"

# Supporting Document: https://github.com/center-for-threat-informed-defense/attack_to_cve
csv_url = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv'

download = requests.get(csv_url).content

data = pd.read_csv(io.StringIO(download.decode('utf-8')))

# Replace 'access_key and secret_key with your keys
cmd('navi config keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi config update full')


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-SS-mitre_tags',
            'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


for row in data.values:
    cveid = row[0]
    primary_impact = str(row[1])
    secondary_impact = str(row[2])
    exploit_technique = str(row[3])

    if "nan" not in primary_impact:
        print("Tagging assets based on CVE: {} and impact: {} ".format(cveid, primary_impact))
        cmd('navi enrich tag --c "Mitre" --v "Primary Impact: {}" --cve "{}"'.format(primary_impact, cveid))

    if "nan" not in secondary_impact:
        print("v assets based on CVE: {} and impact: {} ".format(cveid, secondary_impact))
        cmd('navi enrich tag --c "Mitre" --v "Secondary Impact: {}" --cve "{}"'.format(secondary_impact, cveid))

    if "nan" not in exploit_technique:
        print("v assets based on CVE: {} and impact: {} ".format(cveid, exploit_technique))
        cmd('navi enrich tag --c "Mitre" --v "Exploit Technique: {}" --cve "{}"'.format(exploit_technique, cveid))

finish = time.time()

total = finish - start
mins = total / 60

print("The Script took {} seconds or {} minutes".format(total, mins))
