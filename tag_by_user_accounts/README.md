# Known User Tags - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and a SQLite DB to solve some powerful use cases.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

Plugins and the output of a plugin are gold to remediators.  However, they are not asset attributes and therefore are not utilized in the tagging mechanisms of Tenable.io.
Utilizing navi automates the export of the data, searching and parsing for important correlations and decorting the data in Tenable.io using Tags.

In this scenario, we are looking for "User" in the plugin name AND a specific login username found in the output of the focused plugin set.

# How it works

This python script/service utilizes navi to tag assets based on a custom SQL Query.  
Navi utilizes a SQLite database to store vulnerability and asset data coming from the export APIs in Tenable.io.

The query used is below:

    navi tag query "select asset_uuid from vulns where plugin_name LIKE '%user%' and output LIKE '%{a given username}%';"

The tag by query function requires the asset_uuid from the vulns table or the uuid from the asset table.  
This is due to the tag assignments endpoint requiring asset UUIDs for tagging assets.

# What does it do?

The script tags each asset that a given user has a local or AD account on to bring visibility to potential risk.


# Docker command
    docker run -d -e access_key={your Access Key} -e secret_key={your secret Key} -e user={target username} packetchaos/usertags
