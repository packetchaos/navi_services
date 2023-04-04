# Critical Tags - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and a SQLite DB to solve some powerful use cases.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

Plugins, cross references and the output of a plugin are gold to remediators.  However, they are not asset attributes and therefore are not utilized in the tagging mechanisms of Tenable.io.
Utilizing navi automates the export of the data, searching and parsing for important correlations and decorating the data in Tenable.io using Tags.

# How it works

We are weaponizing navi for good! This python script utilizes navi to tag assets based on "Plugin IDs", "Xref" or cross references and text found in the output of a plugin.  Navi utilizes a SQLite database to store vulnerability and asset data coming from the export APIs in Tenable.io.

# What does it do?

The script uses the built in tag functionality to tag each asset. Navi uses a SQLite database and a the Tenable.io tag assignments endpoint to accomplish everything below.  To make these dynamic, put the container command or the script on a cronjob or scheduled task.

The script/service tags assets with the below characteristics:
Note: The Category : Value pair follow the Tag description.  This is what will be seen in Tenable.io should the tag exist.  The Tag is not created if no assets match the navi search.

#### CISA Known Exploits
 * Assets with CISA Known Exploits by Searching for 'CISA' in any cross reference - CISA:Known Vulns

#### Long Scan Times
 * Assets that took longer than 60 minutes to scan using duration in 19506 - Scantime:Over 60 mins

#### Credential issues
 * Assets with credential failures using plugin 104410 - Credential issues:Credential Failure
 * Assets with credential general failures using plugin 21745 - Credential issues:General Failure
 * Assets with insufficient privileges using plugin 110385 - Credential issues:Insufficient Privilege
 * Assets with Intermittent Auth failures using plugin 117885 - Credential issues:Intermittent Auth Failures

#### Asset Visibility
 * Assets that require a reboot using plugins 35453 and 163103' - Reboot:Required
 * Assets running a web server using plugin 24260 - Web Applications:HTTP information Found
 * Docker Hosts using plugin 93561- Docker:Host
 * VMware Hosts using plugin 20301- VMware:Host
 * VMware Machines using plugin 20094- VMware:Virtual Machine

#### Certificate awareness/Issues
 * Assets with an SSL Cert; found using plugin 10863 - SSL Certificates:SSL Detection
 * Assets with an SSL Cert issue from plugin 15901 - Certificate Issues:SSL Cert Expired!
 * Assets with an SSL Certs Issue from plugin 69511 - Certificate Issues:Less than 2048 bits!
 * Assets with an SSL Certs Issue from plugin 51192 - Certificate Issues:Not Trusted!
 * Assets with an SSL Certs Issue from plugin 42981 - Certificate Issues:SSL Cert Expires Soon!
 * Assets with an SSL Certs Issue from plugin 60108 - Certificate Issues:Weak Keys!


# Docker command
    docker run -d {your Access Key} {your secret Key} packetchaos/critical_tags

# navi command
    navi deploy critical-tags

# Accepting Pull Requests
Got ideas for a great tag?  Send a PR or submit a Ticket and I will add it to my backlog.
