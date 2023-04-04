import sys
from tenable.io import TenableIO
import time

start = time.time()

access_key = str(sys.argv[1])
secret_key = str(sys.argv[2])
trigger = str(sys.argv[3])
fire = str(sys.argv[4])

url = "https://cloud.tenable.com"

tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Dependent Scans - 0.0.1")

print("\nLaunching scan {}\n".format(trigger))
tio.scans.launch(trigger)

check_status = True

print("Checking the Status of scan {} every 60 seconds\n".format(trigger))
while check_status:
    # No need to slam the API; Let's check every Min
    time.sleep(60)

    # Check the status of our trigger scan
    scan_status = tio.scans.status(trigger)

    if 'completed' in scan_status:
        scan_data = tio.get('{}/scans/{}'.format(url, str(trigger))).json()

        print("Launching your second scan:{}".format(fire))
        tio.scans.launch(fire)
        # Breaking the loop
        check_status = False

    if scan_status == 'aborted':
        print("Triggered Scan was aborted Check the scan")
        break

    if scan_status == 'imported':
        print("Triggered Scan was imported and can't be used for this purpose.")
        break
finish = time.time()

total = finish - start
mins = total / 60

print("\nThe Script took {} seconds or {} minutes".format(total, mins))
