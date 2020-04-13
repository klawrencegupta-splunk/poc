#List of F5 iControl APIs whcih are global, that is these apis should be fetched in only one partition, rather than all specified in the F5 server.
#This is for user-customized templates before Splunk_TA_f5-bigip v2.3.0, in which parameter '--GLOBAL' has not been introduced yet.


#########################
#        System         #
#########################
System.Disk.get_list_of_logical_disks
System.Statistics.get_oneconnect_statistics
System.Statistics.get_http_statistics
System.Statistics.get_ftp_statistics
System.Statistics.get_icmp_statistics
System.Statistics.get_icmpv6_statistics
System.Statistics.get_tcp_statistics
System.Statistics.get_udp_statistics
System.Statistics.get_ip_statistics
System.Statistics.get_ipv6_statistics
System.Statistics.get_dns_statistics
System.Statistics.get_dnssec_statistics
System.Statistics.get_global_statistics
System.Statistics.get_global_tmm_statistics
System.Statistics.get_gtm_global_statistics
System.Statistics.get_global_host_statistics
System.Statistics.get_client_ssl_statistics
System.SystemInfo.get_system_information
System.SystemInfo.get_system_id
System.SystemInfo.get_product_information
System.SystemInfo.get_hardware_information
System.SystemInfo.get_uptime
System.SystemInfo.get_cpu_usage_information
System.SystemInfo.get_global_cpu_usage_extended_information
System.SystemInfo.get_memory_usage_information
System.SystemInfo.get_disk_usage_information


#########################
#      Networking       #
#########################
Networking.Interfaces.get_all_statistics
Networking.Interfaces.get_list
Networking.AdminIP.get_list


#########################
#      Management       #
#########################
Management.Provision.get_provisioned_list
Management.UserManagement.get_authentication_method
Management.UserManagement.get_default_partition
Management.UserManagement.get_default_role
Management.UserManagement.get_my_permission
Management.UserManagement.get_remote_console_access
Management.UserManagement.get_list

