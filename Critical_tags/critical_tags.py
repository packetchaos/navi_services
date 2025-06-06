from os import system as cmd
import os
import time
start = time.time()

access_key = os.environ['access_key']
secret_key = os.environ['secret_key']

# Replace 'access_key and secret_key with your keys
cmd('navi config keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi config update full')

# Tag assets based on 19506 Data
cmd('navi enrich tag --c "Scan Time" --v "Over 60 Mins" --scantime 60')

# Credential issues
cmd('navi enrich tag --c "Credential Issues" --v "Credential Failure" --plugin 104410')
cmd('navi enrich tag --c "Credential Issues" --v "General Failure" --plugin 21745')
cmd('navi enrich tag --c "Credential Issues" --v "Insufficient Privilege" --plugin 110385')
cmd('navi enrich tag --c "Credential Issues" --v "Intermittent Auth Failure" --plugin 117885')

# Tags on CISA Known Vulns
cmd('navi enrich tag --c "CISA" --v "Known Vulns" --xrefs CISA')

# Docker hosts
cmd('navi enrich tag --c "Docker" --v "Host" --plugin 93561')

# VMware Hosts
cmd('navi enrich tag --c "VMWare" --v "Host" --plugin 20301')
cmd('navi enrich tag --c "VMWare" --v "Virtual Machine" --plugin 20094')

# Website found
cmd('navi enrich tag --c "Web Applications" --v "HTTP information Found" --plugin 24260')

# Requires a reboot
cmd('navi enrich tag --c "Reboot" --v "Required" --plugin 35453')
cmd('navi enrich tag --c "Reboot" --v "Required" --plugin 163103')

# Certificate Issues
cmd('navi enrich tag --c "SSL Certificates" --v "SSL Detection" --plugin 10863')
cmd('navi enrich tag --c "Certificate Issues" --v "SSL Cert Expired!" --plugin 15901')
cmd('navi enrich tag --c "Certificate Issues" --v "Less than 2048 bits!" --plugin 69551')
cmd('navi enrich tag --c "Certificate Issues" --v "Not Trusted!" --plugin 51192')
cmd('navi enrich tag --c "Certificate Issues" --v "SSL Cert Expires Soon!" --plugin 42981')
cmd('navi enrich tag --c "Certificate Issues" --v "Weak Keys!" --plugin 60108')

finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))


