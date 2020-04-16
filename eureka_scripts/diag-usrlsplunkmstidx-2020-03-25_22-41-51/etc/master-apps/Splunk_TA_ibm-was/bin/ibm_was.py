import sys
import os.path as op
import Queue
import time

import ta_util2.utils as utils
import ta_util2.log_files as log_files
import was_consts as c

all_logs = log_files.get_all_logs()
all_logs.append(c.was_log)

_LOGGER = utils.setup_logging(c.was_log)

import ta_util2.job_scheduler as sched
import ta_util2.job_source as js
import ta_util2.data_loader as dl
import ta_util2.event_writer as event_writer
import ta_util2.configure as conf
import ta_util2.state_store as ss
import was_inputs_gen as gen
import was_hpel_job_factory as jf
import was_config as wc


def generate_was_inputs(was_config):
    fm_stanza = c.was_file_monitor_settings
    if not utils.is_true(was_config[fm_stanza][c.was_file_monitor_enabled]):
        return

    was_config[fm_stanza].update(was_config[c.meta])
    was_config[fm_stanza].update(was_config[c.was_global_settings])

    was_dir = op.dirname(op.dirname(op.abspath(__file__)))
    was_conf = op.join(was_dir, "local", c.was_conf_file)

    try:
        conf_mtime = op.getmtime(was_conf)
    except OSError:
        return

    appname = utils.get_appname_from_path(op.abspath(__file__))
    store = ss.StateStore(was_config[c.meta], appname)
    res = store.get_state(c.was_fm_ck)
    if res and res["last_mtime"] == conf_mtime:
        return

    _LOGGER.info("Detect %s changed", was_conf)
    _LOGGER.info("Start generating inputs.conf.")
    gen.generate_was_inputs(was_config[fm_stanza])

    # commit this generation
    ck = {"last_mtime": conf_mtime, "version": 1}
    store.update_state(c.was_fm_ck, ck)

    # FIXME, _reload for inputs.conf
    _LOGGER.info("End of generating inputs.conf.")


def _setup_signal_handler(data_loader):
    """
    Setup signal handlers
    @data_loader: data_loader.DataLoader instance
    """

    def _handle_exit(signum, frame):
        _LOGGER.info("WAS TA is going to exit...")
        data_loader.tear_down()

    utils.handle_tear_down_signals(_handle_exit)


def _get_file_change_handler(data_loader, meta_configs):
    def reload_and_exit(changed_files):
        _LOGGER.info("Reload conf %s", changed_files)
        conf.reload_confs(changed_files, meta_configs[c.session_key],
                          meta_configs[c.server_uri])
        data_loader.tear_down()

    return reload_and_exit


def _setup_logging(loglevel="INFO", refresh=False):
    for logfile in all_logs:
        utils.setup_logging(logfile, loglevel, refresh)


class ModinputJobSource(js.JobSource):

    def __init__(self, stanza_configs):
        self._done = False
        self._job_q = Queue.Queue()
        self.put_jobs(stanza_configs)

    def put_jobs(self, jobs):
        for job in jobs:
            self._job_q.put(job)

    def get_jobs(self, timeout=0):
        jobs = []
        try:
            while 1:
                jobs.append(self._job_q.get(timeout=timeout))
        except Queue.Empty:
            return jobs


def collect_hpel_log(was_config):
    tasks = wc.get_hpel_tasks(was_config)
    if not tasks:
        return

    writer = event_writer.EventWriter()
    job_src = ModinputJobSource(tasks)
    job_factory = jf.HpelJobFactory(job_src, writer)
    job_scheduler = sched.JobScheduler(job_factory)
    data_loader = dl.GlobalDataLoader.get_data_loader(
        tasks, job_scheduler, writer)
    callback = _get_file_change_handler(data_loader, was_config[c.meta])
    conf_monitor = wc.WasConfMonitor(callback)
    data_loader.add_timer(conf_monitor.check_changes, time.time(), 60)

    _setup_signal_handler(data_loader)
    data_loader.run()


def run():
    was_config, stanzas = wc.get_was_configs()
    log_level = was_config[c.was_global_settings].get(c.log_level, "INFO")
    _setup_logging(log_level, True)
    generate_was_inputs(was_config)

    if not stanzas:
        return
    collect_hpel_log(was_config)


def do_scheme():
    """
    Feed splunkd the TA's scheme
    """

    print """
    <scheme>
    <title>Splunk Add-on for IBM WebSphere Application Server</title>
    <description>Collects IBM WebSphere Application Server logs</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>true</use_single_instance>
    <endpoint>
      <args>
        <arg name="name">
          <title>IBM WAS TA Configuration</title>
        </arg>
        <arg name="was_data_input">
          <title>WAS Data Input</title>
        </arg>
    </endpoint>
    </scheme>
    """


def usage():
    """
    Print usage of this binary
    """

    hlp = "%s --scheme|--validate-arguments|-h"
    print >> sys.stderr, hlp % sys.argv[0]
    sys.exit(1)


def main():
    """
    Main entry point
    """

    args = sys.argv
    if len(args) > 1:
        if args[1] == "--scheme":
            do_scheme()
        elif args[1] == "--validate-arguments":
            sys.exit(0)
        elif args[1] in ("-h", "--h", "--help"):
            usage()
        else:
            usage()
    else:
        _LOGGER.info("Start WAS TA")
        run()
        _LOGGER.info("Stop WAS TA")
    sys.exit(0)


if __name__ == "__main__":
    main()
