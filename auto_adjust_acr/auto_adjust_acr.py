import os
from os import system as cmd
import time
from tenable.io import TenableIO
import subprocess
start = time.time()
import pprint


access_key = os.environ['access_key']
secret_key = os.environ['secret_key']
tag_category = os.environ['tag_category']
tag_value = os.environ['tag_value']
acr_value = os.environ['acr_change']

note ='Navi updated the ACR by(+/-) or set to {}'.format(acr_change)

url = "https://cloud.tenable.com"

tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Agent Group Tags - 0.0.2")

# Replace 'access_key and secret_key with your keys
#cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database and limit the data by the tag provided
#cmd('navi update assets --c {} --v {}'.format(tag_category, tag_value))

#cmd('navi update vulns --c {} --v {}'.format(tag_category, tag_value))

def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-Agent-Group-tags',
            'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


acr_data = subprocess.check_output('navi explore data query "select acr from assets;"', shell=True)
list_of_acrs = acr_data.decode('utf-8')

# Find Current ACR Values
for acr in eval(list_of_acrs):
    score = acr[0]
    new_score = 0
    print(acr[0])

    if "inc" in acr_change:
        try:
            print("increase by :{} from: {}".format(acr_change[3:], score))
            new_score = score + int(acr_change[3:])
            if new_score > 10:
                new_score = 10
            print("Setting the score to: ", new_score)
        except TypeError:
            pass
    elif "dec" in acr_change:
        try:
            print("decrease", acr_change[3:])
            new_score = score - int(acr_change[3:])
            if new_score < 1:
                new_score = 1
            print("Setting the score to: ", new_score)
        except TypeError:
            pass

    elif int(acr_change[3:]) > 10:
        print("Too big of a number.\n I set it to the highest available")
    elif int(acr_change[:3]) < 1:
        print("Too small of a number")
    else:
        #print(eval(acr_change))
        print('navi enrich acr --score {} --c {} --v {} --note "{}"'.format(acr_change[:3], tag_category, tag_value, note))

