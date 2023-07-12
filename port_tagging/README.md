# Port Tagging - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and a SQLite DB to solve some powerful use cases.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

Open ports are not red flashing signs in Tenable.io or nessus.  However, some remediators find it valuable to know what ports are open on the systems they own.  
The easiest way to accomplish this is through decorating the asset via tags.

# How it works

We are weaponizing navi for good! This python script utilizes navi to tag assets based open ports.  
Navi utilizes a SQLite database to store vulnerability and asset data coming from the export APIs in Tenable.io.


# What does it do?

The script uses the built-in navi tag functionality to tag each asset.

Navi uses a SQLite database and the Tenable.io tag assignments endpoint to accomplish tagging assets by open ports.  To make these dynamic, put the container command or the script on a cronjob or scheduled task.

Each Open Port found in Tenable.io will be used to Tag all of the agents updated in the last 90 days with the group name.

Open Port : Port : {Port number}

# Docker command
    docker run -d -e access_key={your Access Key} -e secret_key={your secret Key} packetchaos/port_tagging

