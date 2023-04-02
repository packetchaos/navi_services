import sys
from tenable.io import TenableIO
import time

start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])
trigger = str(sys.argv[3])
fire = str(sys.argv[4])
targets = sys.argv[5]

url = "https://cloud.tenable.com"

tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Discovery than VulnScan - 0.0.1")

print("\nLaunching scan {}\n".format(trigger))
tio.scans.launch(trigger, targets=[targets])

check_status = True

# Used to grab our assets from the trigger scan.
text_targets = []

print("Checking the Status of scan {} every 60 seconds\n".format(trigger))
while check_status:
    # No need to slam the API; Let's check every Min
    time.sleep(60)

    # Check the status of our trigger scan
    scan_status = tio.scans.status(trigger)

    if 'completed' in scan_status:
        # Grab the hosts from the trigger scan. Current limit is 5000.
        scan_data = tio.get('{}/scans/{}'.format(url, str(trigger))).json()

        # We only need the IPs/hostnames from the scan
        for host in scan_data['hosts']:
            text_targets.append(host['hostname'])

        print("Launching your new scan: {} with the new targets:\n{}\n "
              "\nTotal Asset Count:{}".format(fire, text_targets, len(text_targets)))
        # launch the scan with new targets
        tio.scans.launch(fire, targets=text_targets)
        check_status = False
    else:
        print("Triggered Scan was aborted, imported or some other scan related issue.  Check the scan")
        break

finish = time.time()

total = finish - start
mins = total / 60

print("\nThe Script took {} seconds or {} minutes".format(total, mins))
