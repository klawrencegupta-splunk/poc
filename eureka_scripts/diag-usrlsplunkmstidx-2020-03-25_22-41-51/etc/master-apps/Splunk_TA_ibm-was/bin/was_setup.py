"""
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the
configuration page.

    handleList method: lists configurable parameters in the configuration page
    corresponds to handleractions = list in restmap.conf

    handleEdit method: controls the parameters and saves the values
    corresponds to handleractions = edit in restmap.conf
"""

from datetime import datetime
import splunk.clilib.cli_common as scc
import splunk.admin as admin

import ta_util2
from ta_util2 import utils
from ta_util2 import configure as conf
import was_inputs_gen as gen
import was_consts as c

_LOGGER = utils.setup_logging("ta_was_setup")


class ConfigApp(admin.MConfigHandler):
    was_args = (c.was_install_dir, c.index, c.log_level,
                c.was_file_monitor_enabled, c.file_whitelist, c.exclude_dirs,
                "gen_msg", c.hpel_collection_enabled, "excluded_profiles",
                c.level, c.min_level, c.max_level, c.start_date, c.duration)

    conf_file = c.was_conf

    def setup(self):
        """
        Set up supported arguments
        """

        if self.requestedAction == admin.ACTION_EDIT:
            for arg in self.was_args:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        """
        Read the initial values of the parameters from the custom file
        ibm_was.conf, and write them to the setup screen.

        If the app has never been set up, uses default/ibm_was.conf.

        If app has been set up, looks at local/ibm_was.conf first,
        then looks at default/ibm_was.conf only if there is no value for
        a field in local/ibm_was.conf

        For text fields, if the conf file says None, set to the empty string.
        """

        _LOGGER.info("start list")
        conf.reload_confs((self.conf_file,),
                          self.getSessionKey(), scc.getMgmtUri())

        confDict = self.readConf(self.conf_file)

        if confDict is not None:
            for stanza, settings in confDict.items():
                for key, val in settings.items():
                    if key in self.was_args and val is None:
                        val = ""
                    confInfo[stanza].append(key, val)
            gen_msg = gen.get_generation_msg()
            if not gen_msg:
                gen_msg = ("When saved, refresh this page to get the latest " 
                           "file monitoring inputs.conf generation status")
            confInfo[c.was_file_monitor_settings].append("gen_msg", gen_msg)
        _LOGGER.info("end list")

    def handleEdit(self, confInfo):
        """
        After user clicks Save on setup screen, take updated parameters,
        normalize them, and save them somewhere
        """

        _LOGGER.info("start edit")
        args = self.callerArgs.data
        for arg in self.was_args:
            if args.get(arg, None) and args[arg][0] is None:
                args[arg][0] = ""

        if c.was_install_dir in args:
            self._handleUpdateGlobalSettings(confInfo, args)

        if c.hpel_collection_enabled in args:
            self._handleUpdateHpelSettings(confInfo, args)

        if c.was_file_monitor_enabled in args:
            self._handleUpdateFileMonitorSettings(confInfo, args)

        conf.reload_confs((self.conf_file,),
                          self.getSessionKey(), scc.getMgmtUri())

        _LOGGER.info("end edit")

    def _getSettings(self, stanza, args, keys, confInfo):
        settings = {}
        for k in keys:
            if args.get(k):
                settings[k] = args[k]
                confInfo[stanza].append(k, args[k][0])
        return settings

    def _handleUpdateGlobalSettings(self, confInfo, args):
        keys = (c.was_install_dir, c.index, c.log_level)
        stanza = c.was_global_settings
        settings = self._getSettings(stanza, args, keys, confInfo)
        """
        if not settings.get(c.was_install_dir, [""])[0]:
            msg = "WebSphere installation is not specified"
            _LOGGER.error(msg)
            raise Exception(msg)
        """

        self.writeConf(self.conf_file, stanza, settings)

    def _handleUpdateHpelSettings(self, confInfo, args):
        keys = (c.hpel_collection_enabled, c.start_date, c.level, c.min_level,
                c.max_level, c.duration, c.excluded_profiles)
        stanza = c.was_hpel_settings
        settings = self._getSettings(stanza, args, keys, confInfo)
        start_date = settings[c.start_date][0]
        if start_date:
            try:
                datetime.strptime(start_date, "%m/%d/%y %H:%M:%S:%f")
            except ValueError:
                msg = ("Invalid start date=%s since it isn't in the "
                       "format of MM/dd/yy H:m:s:S" % start_date)
                _LOGGER.error(msg)
                raise Exception(msg)

        self.writeConf(self.conf_file, stanza, settings)

    def _handleUpdateFileMonitorSettings(self, confInfo, args):
        keys = (c.was_file_monitor_enabled, c.file_whitelist, c.exclude_dirs)
        stanza = c.was_file_monitor_settings
        settings = self._getSettings(stanza, args, keys, confInfo)
        self.writeConf(self.conf_file, stanza, settings)

        if utils.is_true(settings.get(c.was_file_monitor_enabled, [0])[0]):
            _LOGGER.info("Signal the backend to gen inputs.conf")
            gen.create_generation_msg(
                "Signaled the backend to generate inputs.conf. "
                "Refresh this page to get the latest status.")
        else:
            gen.remove_generation_msg()


admin.init(ConfigApp, admin.CONTEXT_APP_ONLY)
