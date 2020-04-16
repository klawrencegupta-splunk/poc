#!$SPLUNK_HOME/bin/python

# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
import sys
from hydra.hydra_gateway import bootstrap_web_service


def get_gateway_config(session_key):
    """
    Gets the hydra gateway config from splunk

    RETURNS tuple of port, service_log_level, access_log_level
    """
    from hydra.models import HydraGatewayStanza

    stanza = HydraGatewayStanza.from_name("gateway", "SA-Hydra", session_key=session_key)
    if not stanza:
        return 8008, "", ""
    else:
        return stanza.port, stanza.service_log_level, stanza.access_log_level


if __name__ == "__main__":
    #Get Gateway Configuration
    session_key = sys.stdin.readline().strip("\r\n")
    port, service_log_level, access_log_level = get_gateway_config(session_key)

    #Build Gateway
    server = bootstrap_web_service(port, service_log_level, access_log_level)
    server.start()