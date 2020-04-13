######Configure DNS Logging######
1. Logon to each AD DNS Server.
2. Open DNS Application under Control Panel\Administrative Tools
3. Right click your server name in the left panel and select 'Properties'
4. Select Debug Logging tab
5. Tick the following tick boxes.  Leave the rest unticked.
	Log Packets for Debugging
	Packet Direction - Incoming
	Packet Direction - Outgoing
	Packet Contents - Queries / Transfers
	Other Options - Details
6. In 'File path and name' specify the folder that you want to export the logs to.  Recommended to use a non system drive. I used 'D:\Logs\DNS\dns.log'
7. If you have a different name make sure you update the inputs.conf file in Splunk_TA_MSDNS\local\inputs.conf.
8. Deploy app to Indexer, Search Head and Universal Forwarder.
