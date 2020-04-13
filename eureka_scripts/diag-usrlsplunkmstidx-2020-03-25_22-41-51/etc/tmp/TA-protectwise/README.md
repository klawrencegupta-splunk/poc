## **Table of Contents**

### **OVERVIEW**

- About the TA-ProtectWise App for Splunk
- Release notes
- Support and resources

### **INSTALLATION**

- Hardware and software requirements
- Installation steps

### **USER GUIDE**

- Key concepts

### **OVERVIEW**

#### **About the TA-ProtectWise App for Splunk**

| Author | ProtectWise |
| --- | --- |
| App Version | 1.0.0 |
| Vendor Products | ProtectWise Syslog Emitter v2.61 and above |
| Has index-time operations | True |
| Create an index | True |
| Implements summarization | False |

The TA-ProtectWise is a solution that enables the viewing and organizing of ProtectWise technical anomaly events and observations in Splunk. It also allows the ability to pivot into the ProtectWise Visualizer from within your Splunk deployment to enhance your ability to detect and respond to attacks and/or network anomalies.

##### **Scripts and binaries**

N/A

#### **Release notes**

##### **About this release**

Version 1.0.0 of the TA-ProtectWise App for Splunk is compatible with:

| **Splunk Enterprises versions:** | **6.x and above** |
| --- | --- |
| CIM: | N/A |
| Platforms: | Platform Independent |
| Vendor Products: | ProtectWise Syslog Emitter v2.61 and above |
| Lookup file changes: | None |

##### **New features**

**Support**

- Domestic and International Support URL: [https://support.protectwise.com](https://support.protectwise.com)
- Email: [support@protectwise.com](support@protectwise.com)
- Support hours: 24/7 for Web/Email, Weekday business hours for phone. 
- Response: all cases submitted will be confirmed via email

## **INSTALLATION AND CONFIGURATION**

### **Hardware and software requirements**

#### **Hardware requirements**

TA-ProtectWise App for Splunk supports the following server platforms in the versions supported by Splunk Enterprises.

- Platform Independent

#### **Software requirements**

To function properly, TA-ProtectWise App for Splunk requires the following software:

- ProtectWise Syslog Emitter v2.61 and above

#### **Splunk Enterprise system requirements**

This app runs on Splunk Enterprises. All of the Splunk Enterprises system requirements apply. [http://docs.splunk.com/Documentation/Splunk/latest/Installation/Systemrequirements](http://docs.splunk.com/Documentation/Splunk/latest/Installation/Systemrequirements)

#### **Download**

Download the TA-ProtectWise App for Splunk at []()

#### **Installation steps**

To install and configure this app on your supported platform, follow these steps:

##### Web UI #####

1. Click on the gear next to Apps
2. Click on Install App from File
3. Chose downloaded file and click upload
4. Restart Splunk

##### Configuration Files #####

1. Untar downloaded file
2. Copy or move protectwise folder to $SPLUNKBASE/etc/apps directory
3. Restart Splunk


##### Deploy to single server instance

Install TA-Protectwise using one of the methods described above.

##### Deploy to distributed deployment

**Install to search head**

TA-Protectwise doesn't need to be installed onto search heads.

**Install to indexers**

Install TA-Protectwise using one of the methods described above.

**Install to forwarders**

Install TA-Protectwise using one of the methods described above.

#### **Configuration**

**TA-ProtectWise:** This TA contains input.conf configurations for forwarders as well as indexes.conf and props.conf for indexers.

Has index-time properties: True

Creates custom index: True

**Indexers:**
1. Place TA-protectwise in the $SPLUNK\_HOME/etc/apps dir of your indexer(s).
Creates custom index protectwise that is needed for use within ProtectWise App for Splunk.

**Forwarders:**
1. Place TA-protectwise in the $SPLUNK\_HOME/etc/apps dir of your forwarder(s).
2. For the inputs.conf for the forwarders: The default location for the ProtectWise Emitter logs is as follows: /tmp/spl. If you have updated this location, update the inputs.conf file with the path for each monitor stanza. (Be sure to include the preceeding forward slash so there will be a total of three forward slashes after &#39;monitor:&#39;)

[monitor://&lt;custom\_path&gt;/events.out]

index = protectwise

sourcetype = protectwise\_emitter

## **USER GUIDE**

### **Key concepts for TA-ProtectWise App for Splunk**

The TA-ProtectWise App uses the power of ProtectWise and combines it with the search power of Splunk. Investigations of Events and Observations can take advantage of Splunk&#39;s business intelligence interface and search system UI that allows users to pivot into the ProtectWise Visualizer.

**Transfom/Alias**

Field aliases that normalize the ProtectWise data to fit the CIM can be found in the props.conf file in the app.
