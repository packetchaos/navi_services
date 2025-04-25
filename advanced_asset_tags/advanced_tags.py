from os import system as cmd
import sys
import time
import requests
from tenable.io import TenableIO
import subprocess
import pandas as pd
import io
import os

start = time.time()

access_key = os.environ['access_key'] #str(sys.argv[1])
secret_key = os.environ['secret_key'] #str(sys.argv[2])

url = "https://cloud.tenable.com"

cmd('navi config keys --a "{}" --s "{}"'.format(access_key, secret_key))

# Update the navi database for tagging on vulns
cmd('navi config update full')


tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build="Advanced Asset Tags - 0.0.1")


def grab_headers():
    return {'Content-type': 'application/json', 'user-agent': 'Navi-SS-Scan_tags', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


# run the navi automation command
cmd('navi action automate --sheet "advanced_tags" --name "tvm_example.xlsx"')