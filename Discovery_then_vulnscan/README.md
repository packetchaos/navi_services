# Discovery then Vulnscan - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and pytenable to reduce scan complexity and potentially reduce overall scantime.  Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

In environments where subnets are under ~50% populated you may find a minor to traumatic decrease in total scan time when your vulnerability scan is focused on the assets discovered. Nessus on average will take 10 seconds for every dead host in a vuln scan.  When a subnet is underpopulated, Nessus can spend a lot of time evaluating dead hosts.

# How it works
 Below is a step by step to unlock this power:
1. Setup a Discovery Scan, then Grab the Scan ID using Navi or the Tenable.io UI.
2. Setup a Vulnerability Scan then Grab the Scan ID using Navi or the Tenable.io UI.
3. Use the Discovery Scan as the 'trigger' with your large subnet(s) as the 'targets'
4. Use the Vulnerability Scan as the 'fire' which will be based on the responding IPs
5. Deploy the container as shown below.

The script will launch the discovery scan with your 'targets' and follow it's progress.  

When the scan is finished, the assets that responded in the discovery scan will be moved to the vulnerability scan.

The script finishes and the container is destroyed once the vuln scan is launched.

# Docker command
    docker run -d -e access_key={Your access Key} -e secret_key={Your secret Key} -e trigger={first scan id} -e fire={second scan id} -e targets={Discovery Subnets} packetchaos/discovery_then_vulnscan

# navi command
    navi deploy discoverythenvulnscan --trigger {scan id} --fire {scan id} --targets {subnet(s)}
