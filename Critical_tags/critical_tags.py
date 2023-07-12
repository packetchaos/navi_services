from os import system as cmd
import os
import time
start = time.time()

access_key = os.environ['access_key'] # str(sys.argv[1])
secret_key = os.environ['secret_key'] # str(sys.argv[2])

url = "https://cloud.tenable.com"

# Replace 'access_key and secret_key with your keys
cmd('navi keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi update full')


# Do the authentication bits :)
def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'navi-SS-Critical_tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# Tag assets based on 19506 Data
cmd('navi tag --c "Scan Time" --v "Over 60 Mins" --scantime 60')

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

finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


