# Splunk - vCPU Reports

This app is provided as part of a POC between Splunk our design partners and is not an offiically supported Splunk app. All requests for support should be submitted as  [Issues](https://github.com/klawrencegupta-splunk/poc/issues)  to the GitHub repository and/or  [klawrencegupta@splunk.com](mailto:klawrencegupta@splunk.com).

This app should run on the Monitoring Console as it will need access to all Splunk nodes in the deployment.

### Screenshots
https://docs.google.com/document/d/1QVBpYpDXZxEkrD0AOAXhkFwBOFhluu58ST33dXdUvlg/edit?usp=sharing

### Dashboards

#### Questionare Server Discovery Snapshot

An automated dashboard to gather static information from the Splunk Deployment along with brief customer questionare.

-   Total Ingest GB/day - requires access to the license_usage.log
-   License Detail - requires access to the license master/services/licenser/licenses/ REST endpoint
-   Virtual Cores by Host - requires REST access to /services/server/info for all peered nodes
-   Search Statistics - _introspection + PerProcess event data
-   Search Concurrency -_introspection + PerProcess event data
-   User Concurrency - _audit index
-   of Active Dashboards -_introspection + PerProcess event data
-   Total Dashboard Count by Splunk App - REST access to search heads /servicesNS/-/-/data/ui/views

#### Splunk - vCPU Reporting

-   Total CPU Utilization - This is a gross measure of the sum of the maximum CPU Utilization by Category/Total Compute Allocated over the period of time chosen (24 hour default)
	- *version 1.1 update includes a logic fix that under-reported CPU utilization overall.*
-   Total Allocated Compute by Host - from REST| rest splunk_server=* /services/server/info
	-  *version 1.1. update adds Virtual Cores by Server Roles panel*
-   Distribution of Total Allocated Compute by Usage Category - Max CPU utilzation by Category
	- *version 1.1 update includes Extrapolated Utilization & more accurate CPU usage*
-   Distribution of Average vCPU activity - pie chart showing distribution of activity
-   Distribution Details of vCPU by Category - breakdown by data.process_type using _introspection + PerProcess event data

#### Splunk - vCPU Reporting - Index Details
*Version 1.1 removes the Trellis board for PDF generation*

-   Index Service - CPU Utilization - Max/Average and Stdev of CPU Util for the Index(Ingest Service)
-   Index Service - Reads/Writes Utilization in GB
-   Reads/Writes by Index Service - Hourly Breakdown

#### Splunk - vCPU Reporting - Search Details

*Version 1.1 removes the Trellis board for PDF generation*

-   Distribution of Search Types -_introspection + PerProcess event data
-   Search Process Breakdown -_introspection + PerProcess event data
-   Details - _introspection + PerProcess event data

### Reports

-   vCPU Utilization by Category - Hourly breakdown of stacked CPU utilization by category + table of stats
-   vCPU Utilization by Process Type - Detail - Hourly breakdown of all CPU Utilization by data. process_type
