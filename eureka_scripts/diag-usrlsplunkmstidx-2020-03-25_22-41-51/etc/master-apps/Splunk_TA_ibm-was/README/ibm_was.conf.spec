[was_global_settings]
index = main
was_install_dir =
log_level = INFO

[was_file_monitor_settings]
file_whitelist = \.log*$|\.txt*$|\.traceout*$
exclude_dirs = java,jre,postinstall,deploytool,eclipse64,docs,help,lib,Plugins,plugins,properties,javascript,lafiles
was_file_monitor_enabled = 0

[was_hpel_settings]

# Profiles which do not need to do HPEL data collection or which do not have HPEL turned on.
excluded_profiles =

# start_date should be in MM/dd/yy HH:mm:ss:S" format.
# For example, 6/29/15 23:11:23:456".
# It is interpreted as UTC time.
# The default is 1 day ago.
start_date =

# Valid levels are "FINEST, FINER, FINE, DETAIL, CONFIG, INFO, AUDIT, WARNING, SEVERE, FATAL".
# Ensure the min_level is set to a lower value than max_level. FINEST is the min level and FATAL is the max level.
level =
min_level = INFO
max_level = FATAL
duration = 60
hpel_collection_enabled = 1
