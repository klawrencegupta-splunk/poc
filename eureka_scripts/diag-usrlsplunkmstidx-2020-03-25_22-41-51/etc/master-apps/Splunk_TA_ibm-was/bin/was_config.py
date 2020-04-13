from datetime import datetime, timedelta
import os.path as op
import copy
import logging

import ta_util2.configure as conf
import ta_util2.file_monitor as file_monitor
import ta_util2.utils as utils
import was_common  as wsc
import was_consts as c


_LOGGER = logging.getLogger(c.was_log)


def get_was_configs():
    meta, stanzas = conf.TAConfig.get_modinput_configs()
    conf_mgr = conf.ConfManager(meta[c.server_uri], meta[c.session_key])
    conf_mgr.reload_confs((c.was_conf,), "-")
    configs = conf_mgr.get_conf("-", "-", c.was_conf)
    dict_configs = {config["stanza"]: config for config in configs}
    dict_configs[c.meta] = {
        c.session_key: meta[c.session_key],
        c.checkpoint_dir: meta[c.checkpoint_dir],
        c.server_uri: meta[c.server_uri],
    }
    return dict_configs, stanzas


def _get_hpel_config(was_config):
    hpel_stanza = c.was_hpel_settings
    if not utils.is_true(was_config[hpel_stanza][c.hpel_collection_enabled]):
        _LOGGER.info("HPEL data collection is disabled")
        return

    was_config[hpel_stanza].update(was_config[c.meta])
    was_config[hpel_stanza].update(was_config[c.was_global_settings])
    duration = int(was_config[hpel_stanza].get(c.duration, 60))
    was_config[hpel_stanza][c.duration] = duration
    start_date = was_config[hpel_stanza][c.start_date]
    if not start_date:
        start_date = datetime.utcnow() - timedelta(days=1)
        start_date = start_date.strftime("%m/%d/%y %H:%M:%S:000 UTC")
    else:
        start_date = start_date.strip()
        if not start_date.endswith("UTC"):
            start_date += " UTC"

        try:
            datetime.strptime(start_date, "%m/%d/%y %H:%M:%S:%f %Z")
        except ValueError:
            msg = ("Invalid start date=%s since it isn't in the "
                   "format of MM/dd/yy H:m:s:S" % start_date)
            _LOGGER.error(msg)
            raise Exception(msg)

    was_config[hpel_stanza][c.start_date] = start_date

    _LOGGER.debug("start date from configuration %s", start_date)

    levels = ("FINEST", "FINER", "FINE", "DETAIL", "CONFIG", "INFO", "AUDIT",
              "WARNING", "SEVERE", "FATAL")
    level_keys = (c.level, c.min_level, c.max_level)
    for key in level_keys:
        level = was_config[hpel_stanza].get(key)
        if level and level not in levels:
            msg = ("Invalid settings for %s, expected one of %s, but got %s"
                   % (key, levels, level))
            _LOGGER.error(msg)
            raise Exception(msg)

    was_config[hpel_stanza][c.start_date] = start_date
    return was_config


def get_hpel_tasks(was_config):
    was_config = _get_hpel_config(was_config)
    if not was_config:
        return

    hpel_stanza = c.was_hpel_settings
    cmds = wsc.discover_log_viewer_cmds(was_config[hpel_stanza])
    if not cmds:
        return

    configs = []
    for cmd in cmds:
        config = copy.deepcopy(was_config[hpel_stanza])
        config[c.log_viewer] = cmd
        configs.append(config)
    return configs


class WasConfMonitor(file_monitor.FileMonitor):
    def __init__(self, callback):
        super(WasConfMonitor, self).__init__(callback)

    def files(self):
        app_dir = op.dirname(op.dirname(op.abspath(__file__)))
        return (
            op.join(app_dir, "local", c.was_conf_file),
            op.join(app_dir, "bin", "ta_util2", "setting.conf")
        )
