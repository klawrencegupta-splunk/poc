#### Middle language template for F5 BIG-IP iControl API's.
#### Each template record must be of the form:
####call <API Name> [against <API Name> [; <API Name>…][ withField RESULT.<Field Name>]][ breakField RESULT.<Field Name>][ interval <interval value>][ --GLOBAL]



#########################
#        GlobalLB       #
#########################

#GlobalLB.DataCenter
call GlobalLB.DataCenter.get_list against GlobalLB.DataCenter.get_description;get_location_information;get_object_status;get_prober_pool;get_server interval 60
call GlobalLB.DataCenter.get_all_statistics breakField RESULT.statistics

#GlobalLB.Pool
call GlobalLB.Pool.get_list against GlobalLB.Pool.get_cname;get_description; get_fallback_ipv4;get_fallback_lb_method;get_limit;get_member_v2;get_object_status;get_ttl interval 60
call GlobalLB.Pool.get_all_statistics breakField RESULT.statistics

#GlobalLB.ProberPool
call GlobalLB.ProberPool.get_list against GlobalLB.ProberPool.get_description;get_lb_method;get_member;get_member_enabled_state;get_member_object_status;get_member_order;get_object_status interval 60
call GlobalLB.ProberPool.get_all_statistics breakField RESULT.statistics

#GlobalLB.Server
call GlobalLB.Server.get_list against GlobalLB.Server.get_data_center;get_description;get_enabled_state;get_ip_v2;get_limit;get_object_status interval 60
call GlobalLB.Server.get_all_statistics breakField RESULT.statistics

#GlobalLB.VirtualServerV2
call GlobalLB.VirtualServerV2.get_list against GlobalLB.VirtualServerV2.get_address;get_dependency;get_description;get_limit;get_ltm_virtual_server;get_monitor_rule;get_object_status;get_translation interval 60

#GlobalLB.WideIP
call GlobalLB.WideIP.get_list against GlobalLB.WideIP.get_alias;get_application;get_description;get_last_resort_pool;get_lb_method;get_object_status;get_persistence_state;get_persistence_ttl;get_wideip;get_wideip_pool;get_wideip_rule interval 60
call GlobalLB.WideIP.get_all_statistics breakField RESULT.statistics

#GlobalLB.Rule
call GlobalLB.Rule.get_list against GlobalLB.Rule.get_metadata
call GlobalLB.Rule.get_all_statistics breakField RESULT.statistics



#########################
#        LocalLB        #
#########################

#LocalLB.Pool
call LocalLB.Pool.get_list against LocalLB.Pool.get_active_member_count;get_lb_method;get_member_v2;get_minimum_active_member;get_minimum_up_member;get_minimum_up_member_action;get_minimum_up_member_enabled_state;get_object_status;get_simple_timeout interval 60
call LocalLB.Pool.get_all_statistics breakField RESULT.statistics

#LocalLB.NodeAddressV2
call LocalLB.NodeAddressV2.get_list against LocalLB.NodeAddressV2.get_address;get_connection_limit;get_description;get_dynamic_ratio_v2;get_monitor_instance;get_monitor_logging_state;get_monitor_rule;get_monitor_status;get_object_status;get_rate_limit;get_ratio;get_session_status interval 60
call LocalLB.NodeAddressV2.get_all_statistics breakField RESULT.statistics

#LocalLB.VirtualServer
call LocalLB.VirtualServer.get_list against LocalLB.VirtualServer.get_default_pool_name;get_connection_limit;get_connection_mirror_state;get_contribute_to_address_status;get_destination_v2;get_gtm_score;get_object_status;get_related_rule;get_rule interval 60
call LocalLB.VirtualServer.get_all_statistics breakField RESULT.statistics

#LocalLB.VirtualAddressV2
call LocalLB.VirtualAddressV2.get_list against LocalLB.VirtualAddressV2.get_address;get_connection_limit;get_enabled_state;get_object_status;get_status_dependency_scope;get_traffic_group interval 60
call LocalLB.VirtualAddressV2.get_all_statistics breakField RESULT.statistics

#LocalLB.Rule
call LocalLB.Rule.get_all_statistics breakField RESULT.statistics
call LocalLB.Rule.get_list against LocalLB.Rule.get_description;get_ignore_verification;get_verification_status_v2	



#########################
#      Management       #
#########################

#Management.Device
call Management.Device.get_list against Management.Device.get_description;get_location;get_active_modules;get_base_mac_address;get_build;get_cert;get_chassis_id;get_chassis_type;get_comment;get_configsync_address;get_contact;get_description;get_edition;get_failover_state;get_ha_capacity;get_hostname;get_inactive_modules;get_location;get_management_address;get_marketing_name;get_multicast_address;get_optional_modules;get_platform_id;get_primary_mirror_address;get_product;get_secondary_mirror_address;get_software_version;get_timelimited_modules;get_timezone;get_unicast_addresses

#Management.Folder
call Management.Folder.get_list against Management.Folder.get_description;get_device_group;get_no_reference_check_state;get_traffic_group

#Management.Provision
call Management.Provision.get_provisioned_list against Management.Provision.get_custom_cpu_ratio;get_custom_disk_ratio;get_custom_memory_ratio;get_description;get_level --GLOBAL

#Management.UserManagement
call Management.UserManagement.get_authentication_method --GLOBAL
call Management.UserManagement.get_default_partition --GLOBAL
call Management.UserManagement.get_default_role --GLOBAL
call Management.UserManagement.get_my_permission --GLOBAL
call Management.UserManagement.get_remote_console_access --GLOBAL
call Management.UserManagement.get_list	against Management.UserManagement.get_fullname;get_description;get_encrypted_password;get_group_id;get_home_directory;get_home_partition;get_login_shell;get_role;get_user_id;get_user_permission withField RESULT.name --GLOBAL



#########################
#      Networking       #
#########################

#Networking.Interfaces
call Networking.Interfaces.get_all_statistics  breakField RESULT.statistics --GLOBAL
call Networking.Interfaces.get_list against Networking.Interfaces.get_active_media;get_actual_flow_control;get_description;get_dual_media_state;get_enabled_state;get_if_index;get_learning_mode;get_lldp_admin_status;get_lldp_tlvmap;get_mac_address;get_media;get_media_option;get_media_option_sfp; get_media_sfp; get_media_speed;get_media_status;get_mtu interval 60 --GLOBAL

#Networking.SelfIPV2
call Networking.SelfIPV2.get_list against Networking.SelfIPV2.get_address;get_allow_access_list;get_floating_state;get_netmask;get_staged_firewall_policy;get_traffic_group;get_vlan

#Networking.AdminIP
call Networking.AdminIP.get_list against Networking.AdminIP.get_description;get_netmask --GLOBAL

#Networking.VLAN
call Networking.VLAN.get_list against Networking.VLAN.get_auto_lasthop;get_cmp_hash_algorithm;get_customer_id;get_description;get_dynamic_forwarding;get_failsafe_action;get_failsafe_state;get_failsafe_timeout;get_if_index;get_learning_mode;get_member;get_mtu;get_sflow_poll_interval;get_sflow_poll_interval_global;get_sflow_sampling_rate; get_sflow_sampling_rate_global;get_source_check_state;get_static_forwarding;get_true_mac_address;get_vlan_id



#########################
#        System         #
#########################

#System.Disk
call System.Disk.get_list_of_logical_disks against System.Disk.get_logical_disk_device_name;get_logical_disk_format;get_array_member;get_logical_disk_media;get_logical_disk_size;get_logical_disk_space_free;get_logical_disk_space_in_use;get_logical_disk_space_reserved;get_logical_disk_user_mode --GLOBAL

#System.Statistics
call System.Statistics.get_oneconnect_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_http_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_ftp_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_icmp_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_icmpv6_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_tcp_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_udp_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_ip_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_ipv6_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_dns_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_dnssec_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_global_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_global_tmm_statistics breakField RESULT.statistics --GLOBAL
call System.Statistics.get_gtm_global_statistics breakField RESULT.statistics --GLOBAL

#System.SystemInfo
call System.SystemInfo.get_system_information --GLOBAL
call System.SystemInfo.get_system_id  --GLOBAL
call System.SystemInfo.get_product_information --GLOBAL
call System.SystemInfo.get_hardware_information --GLOBAL
call System.SystemInfo.get_uptime interval 60 --GLOBAL
call System.SystemInfo.get_cpu_usage_information breakField RESULT.usages interval 60 --GLOBAL
call System.SystemInfo.get_global_cpu_usage_extended_information  breakField RESULT.statistics interval 60 --GLOBAL
call System.SystemInfo.get_memory_usage_information breakField RESULT.usages interval 60 --GLOBAL
call System.SystemInfo.get_disk_usage_information breakField RESULT.usages --GLOBAL

