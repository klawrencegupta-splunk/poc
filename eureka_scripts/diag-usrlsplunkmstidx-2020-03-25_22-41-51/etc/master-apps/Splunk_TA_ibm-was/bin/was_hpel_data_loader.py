import os.path as op
import re
import threading
from datetime import timedelta, datetime
import time
import logging

from ta_util2.timed_popen import timed_popen
import was_consts as c

_LOGGER = logging.getLogger(c.was_log)


def to_modinput_string(host, index, source, sourcetype, data):
    evt_fmt = ("<event><source>{0}</source><sourcetype>{1}</sourcetype>"
               "<host>{2}</host><index>{3}</index><data><![CDATA[ {4}  ]]>"
               "</data></event>")
    search = re.search
    pat = re.compile("^\[\d{1,2}/\d{1,2}/\d{1,2}\s+\d{1,2}:")
    lines = data.split("\n")
    events = []
    event = []
    for lin in lines:
        if search(pat, lin):
            if event:
                events.append("\n".join(event))
                del event[:]
            event.append(lin)
        else:
            event.append(lin)

    if not events:
        return ""

    events = (evt_fmt.format(source, sourcetype, host, index, e)
              for e in events)
    return "<stream>{}</stream>".format("".join(events))


class HpelDataLoader(object):

    def __init__(self, config):
        """
        @config: dict like object which contains
        {
        log_viewer: logViewer cmd with params,
        server_uri: xxx,
        session_key: xxx,
        checkpoint_dir: xxx,
        duration: yyy,
        }
        """

        self._config = config
        profile = op.basename(
            op.dirname(op.dirname(self._config[c.log_viewer])))
        self._profile = profile
        self._lock = threading.Lock()
        self._ckpts = self._config[c.state_store].get_state(profile)
        if self._ckpts is None:
            self._ckpts = {"version": 1, c.ckpts: {}}
        self._instance_cmds = {}
        self._count = 0

    def collect_data(self):
        if self._lock.locked():
            _LOGGER.info("Last time data collection is not done yet")
            return

        with self._lock:
            if self._count % 10 == 0:
                # Refresh instance cmds every 10 times
                self._instance_cmds = self._get_instance_cmds()
            self._count += 1

            return self._collect_data_with_lock()

    def _collect_data_with_lock(self):
        for server, instances_info in self._instance_cmds.iteritems():
            for instance_info in instances_info:
                self._set_start_stop_date(server, instance_info)
                output = self._do_collect(instance_info[0])
                if output:
                    self._index_data(server, instance_info, output)
                self._write_ckpts(server, instance_info[1][0], instance_info[1][-1])

    def _do_collect(self, log_viewer):
        _LOGGER.info("Start %s", log_viewer)
        output = timed_popen(log_viewer, self._config[c.duration] + 10,
                             op.dirname(log_viewer[0]))
        if output[-1]:
            # timedout
            _LOGGER.error("%s timedout", log_viewer)
            return ""

        if output[1]:
            _LOGGER.error("%s, error=%s", log_viewer, output[1])

        _LOGGER.debug("%s=%s", log_viewer, output[0])
        if not output[0]:
            return ""

        _LOGGER.info("End of %s", log_viewer)
        return output[0]

    def _index_data(self, server, instance_info, output):
        instance_id, start, stop = instance_info[1]
        res = to_modinput_string(
               self._config[c.host], self._config[c.index], server,
               "ibm:was:hpel", output)
        if res:
            self._config[c.event_writer].write_events(res)

    def _write_ckpts(self, server, instance_id, stop):
        ckpts = self._ckpts[c.ckpts]
        if server not in ckpts:
            ckpts[server] = {instance_id: stop}
        else:
            ckpts[server][instance_id] = stop
        self._ckpts[c.timestamp] = time.time()
        self._config[c.state_store].update_state(self._profile, self._ckpts)

    def _set_start_stop_date(self, server, instance_info):
        instance_id = instance_info[1][0]
        start_date, stop_date = self._get_start_stop_date(server, instance_id)
        for idx, option in enumerate(instance_info[0]):
            if option == "-startDate":
                instance_info[0][idx + 1] = start_date
            elif option == "-stopDate":
                instance_info[0][idx + 1] = stop_date
        instance_info[1][-2] = start_date
        instance_info[1][-1] = stop_date

    def _get_start_stop_date(self, server, instance_id):
        """
        @return: (start_date, stop_date)
        """

        collection_interval = self._config[c.duration] / 3600 + 1
        ckpts = self._ckpts[c.ckpts]
        if ckpts and ckpts.get(server) and ckpts.get(server).get(instance_id):
            last_stop = ckpts.get(server).get(instance_id)
        else:
            last_stop = self._config[c.start_date]

        stop_date = datetime.strptime(last_stop, "%m/%d/%y %H:%M:%S:%f %Z")
        next_stop = stop_date + timedelta(hours=collection_interval)
        if next_stop > datetime.utcnow():
            next_stop = datetime.utcnow()
        next_stop = next_stop.strftime("%m/%d/%y %H:%M:%S:000 UTC")
        return (last_stop, next_stop)

    def _get_instance_cmds(self):
        instances_info = self._get_instances_info()
        if not instances_info:
            _LOGGER.info("HPEL log is not turned on for %s", self._profile)
            return {}

        instance_cmds = {}
        for server, instance_ids in instances_info.iteritems():
            if server not in instance_cmds:
                instance_cmds[server] = []

            for instance_id in instance_ids:
                start_date, stop_date = self._get_start_stop_date(
                    server, instance_id)
                cmd = self._construct_full_cmd(
                    start_date, stop_date, instance_id)
                instance_cmds[server].append(
                    [cmd, [instance_id, start_date, stop_date]])
        return instance_cmds

    def _construct_full_cmd(self, start_date, stop_date, instance_id):
        """
        @cmds: logViewer cmd under each profile
        @return: logViewer cmd with params
        """

        options = {
            c.level: "-level",
            c.min_level: "-minLevel",
            c.max_level: "-maxLevel",
        }

        config = self._config
        cmd = [config[c.log_viewer]]
        for k, o in options.iteritems():
            v = config[k]
            if v:
                cmd.append(o)
                cmd.append(v)
        cmd.append("-startDate")
        cmd.append(start_date)
        cmd.append("-stopDate")
        cmd.append(stop_date)
        cmd.append("-instance")
        cmd.append(instance_id)

        return cmd

    def _get_instances_info(self):
        """
        @return: None or dict which contains
        {
            server1: [instance_id1, instance_id2, ...],
            server2: [instance_id11, instance_id22, ...],
        }
        """

        log_viewer = [self._config[c.log_viewer], "-listInstances"]
        output = timed_popen(log_viewer, self._config[c.duration] + 10,
                             op.dirname(log_viewer[0]))
        if output[-1]:
            # timedout
            _LOGGER.error("%s timedout", log_viewer)
            return None

        if not output[0]:
            return None

        _LOGGER.debug("%s=%s", log_viewer, output[0])
        return self._extract_instance_info(output[0])

    def _extract_instance_info(self, output):
        # Extract the server and instance ids
        server_instances = {}
        current_server, state = None, "start"
        server_p = re.compile(r"Using\s*.+[\\|/]+(.+)\s*as\s*repository")
        instance_id_p = re.compile(r"Instance\s*ID")
        instance_p = re.compile(r"^(\d+)\s*\d+/\d+/\d+")
        for lin in output.split("\n"):
            if state == "start":
                m = re.search(server_p, lin)
                if m:
                    current_server = m.group(1).strip()
                    if current_server not in server_instances:
                        server_instances[current_server] = []
                    state = "server"
            elif state == "server":
                m = re.search(instance_id_p, lin)
                if m:
                    state = "instance_start"
            elif state == "instance_start":
                m = re.search(instance_p, lin.lstrip())
                if m:
                    assert current_server in server_instances
                    server_instances[current_server].append(m.group(1))
                else:
                    m = re.search(server_p, lin)
                    if m:
                        current_server = m.group(1)
                        state = "server"
        return server_instances
