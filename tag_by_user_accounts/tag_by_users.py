from os import system as cmd
import sys
import time
import requests
start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])
user = str(sys.argv[3])

url = "https://cloud.tenable.com"

# Replace 'access_key and secret_key with your keys
cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi update full')


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-SS-user_tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


cmd('navi tag --c "Known Users" --v "{}" --query "select asset_uuid from vulns where plugin_name LIKE \'%user%\' and output LIKE \'%{}%\';"'.format(user, user))


finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


