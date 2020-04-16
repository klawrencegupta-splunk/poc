# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
import sys
import urllib2

from splunk import getDefault
import splunk.admin as admin
from splunk.entity import controlEntity
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin']))
import hydra
from hydra.models import HydraGatewayStanza

logger = hydra.setupLogger(log_format='%(asctime)s %(levelname)s [HydraGatekeeper] %(message)s', level="INFO",
                           log_name="hydra_gatekeeper.log", logger_name="hydra-gatekeeper")


class HydraGatekeeperHandler(admin.MConfigHandler):
    def setup(self):
        pass

    def handleList(self, confInfo):
        """
        Provide an authentication proxy for the hydra gateway service, as a
        side effect validate the gateway is turned on and running properly.

        If the gateway is either not on or configured properly return an key
        value of DEFER indicating a client should wait before reauthenticating.
        """
        # Get the hydra gateway config
        stanza = HydraGatewayStanza.from_name("gateway", "SA-Hydra", session_key=self.getSessionKey())
        if stanza is not None and stanza.port is not None:
            port = stanza.port
        else:
            port = 8008
        gateway_uri = "https://" + getDefault("host") + ":" + str(port)

        #Get the Key File
        challenge_key, auth_key = self.get_keys()

        #Validate System
        if not self.validate_challenge_key(gateway_uri, challenge_key):
            #Gateway failed challenge and must be restarted
            logger.warning(
                "gateway failed challenge validation and will be restarted, deferring current authentication request")
            self.restart_gateway()
            #Let the client know they need to re-authenticate
            auth_key = "DEFER"

        #Return the gateway information
        gateway = confInfo["hydra_gateway"]
        gateway['key'] = auth_key

    def get_keys(self):
        """
        Read the challenge and auth keys from the filesystem

        RETURNS tuple of challenge and auth keys
        """
        try:
            f = open(make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run", "hydra_gateway.key"]), 'r')
            challenge_key = f.readline().strip("\r\n")
            auth_key = f.readline().strip("\r\n")
            f.close()
            return (challenge_key, auth_key)
        except IOError:
            return ("", "")

    def validate_challenge_key(self, gateway_uri, key):
        """
        Challenge the local gateway on the expected port and ensure that it is
        running under the proper configuration

        RETURNS True if challenge passes, False otherwise.
        """
        try:
            opener = urllib2.build_opener()
            req = urllib2.Request(gateway_uri + "/hydra/admin/challenge")
            resp = opener.open(req)
            gateway_challenge_key = resp.read().strip("\r\n")
            return gateway_challenge_key == key
        except Exception as e:
            logger.error("[ValidateChallengeKey] could not validate hydra gateway challenge: %s", str(e))
            return False

    def restart_gateway(self):
        """
        Restart the gateway by disabling and enabling the scripted input process
        """
        input_uri = '/servicesNS/nobody/SA-Hydra/data/inputs/script/%24SPLUNK_HOME%252Fetc%252Fapps%252FSA-Hydra%252Fbin%252Fbootstrap_hydra_gateway.py/'
        controlEntity('disable', input_uri + "disable", sessionKey=self.getSessionKey())
        controlEntity('enable', input_uri + "enable", sessionKey=self.getSessionKey())


admin.init(HydraGatekeeperHandler, admin.CONTEXT_NONE)