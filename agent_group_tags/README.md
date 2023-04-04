# Agent Group Tags - A docker Service

This project is a Proof of Concept to show how you can use the Tenable API and a SQLite DB to solve some powerful use cases.  
Wrapping a simple python script into a docker container makes it easy to deploy and reduces deployment risks.  
It also means you don't need to be a developer or a scripter to take advantage of its power.

# Why?

Agent Groups were designed for simplifying scanning agents.  However, it is quite useful to use these asset groupings in Dashboards, reports and remediation goals.
# How it works

We are weaponizing navi for good! This python script utilizes navi to tag assets based agent group membership.  
Navi utilizes a SQLite database to store vulnerability and asset data coming from the export APIs in Tenable.io.


# What does it do?

The script uses the built-in navi tag functionality to tag each asset.

Navi uses a SQLite database and the Tenable.io tag assignments endpoint to accomplish tagging assets by agent group.  To make these dynamic, put the container command or the script on a cronjob or scheduled task.

Each Agent Group found in Tenable.io will be used to Tag all of the agents updated in the last 90 days with the group name.

Agent Group : {Agent Group Name}

# Docker command
    docker run -d {your Access Key} {your secret Key} packetchaos/agent_group_tags

