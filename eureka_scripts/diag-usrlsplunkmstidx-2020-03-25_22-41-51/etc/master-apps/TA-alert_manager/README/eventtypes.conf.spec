[alert_base]
search = index=alerts

[alert_metadata]
search = eventtype=alert_base sourcetype=alert_metadata


[alert_results]
search = eventtype=alert_base sourcetype=alert_results


[incident_change]
search = eventtype=alert_base sourcetype=incident_change