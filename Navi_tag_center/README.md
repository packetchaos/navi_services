# Navi Tag-Center

The navi Tag center was created to simplify complex tagging.  For some, the commandline nature of navi is confusing and intimidating.  This docker container uses Flask to build a small Website to interact with Navi.  Create complex tags using nothing but clicks.

Please feel free to download and provide feedback

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

## Value Snap Shot
* Configure - Allows you to configure the Database with new keys and Exports
* Tag Center - Shown below.  Gives you an easy way to build your tags.
* Assets stats - Get Scan Statistics based on the data in the navi DB
* SLA stats - Deploy a different container per team to utilize different SLAs
* Credential Failures - Assets with Credential Failures with links to Tenable.io Asset data
* Plugin Search - A UI to search the navi database with links to tenable.io asset and vuln data.

## UI Snap Shot
![UI Snapshot](../UI%20Snapshot.png)

# Deploy using local version of Navi
    docker run -d -p 5000:5000 --mount type=bind,source="$(pwd)",target=/usr/src/app/data packetchaos/tag-center

# Deploy using built-in navi DB
    docker run -d -p 5000:5000 packetchaos/tag-center
