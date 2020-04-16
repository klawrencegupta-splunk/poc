[Load Balance]
call LocalLB.Pool.get_list
call LocalLB.Pool.get_list against LocalLB.Pool.get_object_status;get_profile;get_server_ip_tos
call LocalLB.Pool.get_all_statistics breakField RESULT.statistics
call LocalLB.Pool.get_list against LocalLB.Pool.get_statistics
call LocalLB.VirtualServer.get_list against LocalLB.VirtualServer.get_destination_v2;get_profile;get_protocol
call LocalLB.VirtualServer.get_all_statistics breakField RESULT.statistics
call LocalLB.VirtualServer.get_list against LocalLB.VirtualServer.get_statistics
call LocalLB.VirtualAddressV2.get_list against LocalLB.VirtualAddressV2.get_object_status;get_traffic_group;get_netmask

[System Info]
call System.SystemInfo.get_cpu_usage_information breakField RESULT.usages
call System.SystemInfo.get_memory_usage_information breakField RESULT.usages
call System.SystemInfo.get_disk_usage_information breakField RESULT.usages


