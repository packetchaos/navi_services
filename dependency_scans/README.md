# Dependency Scans - A pytenable/docker Service

This project is a Proof of Concept to show how you can use the Tenable API and pytenable to synchronize two scans.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# How it works

The python script utilizes pytenable to do the API heavily lifting.

To launch a scan with pytenable is very simple:

    tio.scans.launch(id)

# Why?

Sometimes you want to ensure one scan finishes before another one begins.  
A vulnerability scan before a compliance scan is a common example.

# What does the script actually do

The scrtipt launches the 'trigger' scan, follows it's progress then launches the 'fire' scan using pytenable primarily the code above..

# Docker command
 docker run -d -e access_key={your Access Key} -e secret_key={your secret Key} packetchaos/dependencyscan
