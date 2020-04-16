# ClamAV add-on app

This technology add-on app is to accompany the ClamAV app.

- ClamAV (https://www.clamav.net/). ClamAV® is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.
- ClamAV is a registred trademark of Sourcefire, Inc. and Cisco Technology, Inc.

The author of this splunk app has no connection whatsoever with ClamAV, Sourcefire, and or Cisco. Other, than I think it's a f'ing cool product and no-one else has made a splunk app for its logs. :)


# Getting Started

This app has been created to work correctly with a stand-alone, distributed, and cloud installs of Splunk. Read the install notes carefully below with your splunk platform in mind.

You will need two apps:
1. ClamAV     https://splunkbase.splunk.com/app/1798/
2. TA-ClamAV  https: <pending>
  a. (this app)  


## New Install

This section is to install on a centralized or stand-alone splunk setup. 

1. Install ClamAV via Splunk UI.
2. Install TA-ClamAV via Splunk UI.
3. Read the index section, below, to enable your correct index settings.
4. Restart the Splunk server.


## Upgrading this app

1. Run the upgrade via the Splunk App management UI.
2. Or use the correct update methodology depending on your distributed design.


## Install for Distributed Splunk designs

For those who are running a distributed Splunk design or HA: ie separate forwarders, search heads, indexers, etc... Please follow these directions, depending on your design YMMV.  Please see this link for more instructions: [http://docs.splunk.com/Documentation/AddOns/released/Overview/Installingadd-ons]

  
1. Install this App on your Search head(s).
    * Do not enable the indexes.conf file.

2. Install this App on your indexer(s).
    * Enable the index and replication: =- indexes.conf
        [clamav]
        repFactor = auto

3. See the README.txt notes to install the ClamAV app.


## Install for Splunk Cloud

I have not used Cloud yet. I believe you install this app via the UI.
Also install the ClamAV app via the UI.


# Getting data
## Syslog notes:

Now that your TA-ClamAV app is installed per your deployment model.

This app makes the assumption that your clamav logs are being sent over syslog using the sourcetype="syslog" with the key works "freshclam" and "clamav" in the syslog process field.

To enable Freshclam syslog logging:
- Edit the /etc/freshclam.conf file
- Make sure setting `LogSyslog yes` is enabled.

To enable clamav syslog logging:
I run my scans like this.
- `/usr/bin/clamscan -i -r $SCAN_DIR $EXCLUDE --log=$LOG_FILE --stdout | logger -i -t clamav -p auth.alert`


## Mac OSX

To gather your clamXav logs on a mac OSX (tested on Yosemite). Make sure clamXav is logging for "scan" and "update" results in your clamXav preferences. Install the Universal Forwarder on a mac and enabled an inputs.conf entry for:

Note: Log location changes depending if you install clamXav manually or via the app store. You may need to validate where your Scan and Update logs are located at. Here are some possible examples:
> [monitor:///Users/<yourusername>/Library/ClamXav/ClamXav-scan.log]
> or
> [monitor:///Users/<yourusername>/Library/Logs/clamXav-scan.log]
> sourcetype=clamav
> index=clamav
>
> [monitor:///Users/<yourusername>/Library/ClamXav/ClamXav-update.log]
> or
> [monitor:///usr/local/clamXav/share/clamav/freshclam.log]
> sourcetype=freshclam
> index=clamav


## Optional scans:

This app support PUA and DLP search results if they are enabled on your scans.
- ClamAV supports scans for DLP like credit cards and social security numbers.
- ClamAV supports scans for PUA.
 - See http://www.clamav.net/doc/pua.html for more information.


# Index Notes:

ClamAV searches are set to look for data in index "clamav". This TA controls the input of data into the index for the ClamAV app. Lately Splunk does not want apps to create indexes be default, so thus you need to create the index file if you wish to use an index.

## Create index file

1. Create file "indexes.conf" in the TA-ClamAV/local/ directory on your indexer.
2. Cut and paste the below data into the file.
3. Restart splunk.

Note: Splunk Cloud users please use the Cloud UI settings to create the "clamav" index.

-----
[clamav]
repFactor = auto    #only use this option if you have a splunk index cluster.
coldPath = $SPLUNK_DB/clamav/colddb
homePath = $SPLUNK_DB/clamav/db
thawedPath = $SPLUNK_DB/clamav/thaweddb
-----

## Use the default index

If you are choosing not to use the "clamav" index and thus the default "main" index, please follow these steps.

1. Delete the local/indexes.conf file.
2. Change index name in default/macros.conf:
   a. "definition = index=main"
3. Restart the Splunk server.


# What's in 1.0.1!

- Verified works with Splunk 6.5 & 6.6.
- Updated to work with Splunk Cloud.
- Validated app through Splunk App builder.
- Fixed macro issue with distributed design. Added distsearch.conf file.


# What's in 1.0!

New TA app!

- Works with Splunk 6.4.
- TA for distributed Splunk designs.


# Support

This is an open source project, no support provided. Please use splunk answers for help and assistance. Author monitors splunk answers and will provide help as best as possible.

