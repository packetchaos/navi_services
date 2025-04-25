# Scan Awareness Tags - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and a SQLite DB to solve some powerful use cases.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

Plugins and the output of a plugin are gold to remediators.  However, they are not asset attributes and therefore are not utilized in the tagging mechanisms of Tenable.io.
Utilizing navi automates the export of the data, searching and parsing for important correlations and decorting the data in Tenable.io using Tags.

# How it works

We are weaponizing navi for good! This python script utilizes navi to tag assets based on "Plugin IDs" and text found in the output of a plugin.  
Navi utilizes a SQLite database to store vulnerability and asset data coming from the export APIs in Tenable.io.


# What does it do?

The script uses the built in tag functionality to tag each asset.

Navi uses a SQLite database and the Tenable.io tag assignments endpoint to accomplish everything below.  To make these dynamic, put the container command or the script on a cronjob or scheduled task.

Note: The Category : Value pair follow the Tag description.  This is what will be seen in Tenable.io should the tag exist.  The Tag is not created if no assets match the navi search.

The script/service tags assets with the below characteristics:

#### Long Scan Time Awareness
 * Assets that took longer than 20 minutes to scan - Scantime:Over 20 mins
 * Assets that took longer than 30 minutes to scan - Scantime:Over 30 mins
 * Assets that took longer than 60 minutes to scan - Scantime:Over 60 mins
 * Assets that took longer than 90 minutes to scan - Scantime:Over 90 mins

#### Credential Failure Awareness
 * Assets with credential failures using plugin 104410 - Credential issues:Credential Failure
 * Assets with credential general failures using plugin 21745 - Credential issues:General Failure
 * Assets with insufficient privileges using plugin 110385 - Credential issues:Insufficient Privilege
 * Assets with Intermittent Auth failures using plugin 117885 - Credential issues:Intermittent Auth Failures

#### Scan ID awareness
 * Tags every asset by the Scan ID that scanned them in the last 35 days. - Scan ID:{scan ID number}


# Docker command
    docker run -d packetchaos/all_tags {your Access Key} {your secret Key} 

# navi command
    navi deploy all-tags
