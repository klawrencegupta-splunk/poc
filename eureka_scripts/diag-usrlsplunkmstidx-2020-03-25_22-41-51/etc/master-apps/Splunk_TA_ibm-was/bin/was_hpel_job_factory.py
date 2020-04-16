"""
Create scheduling jobs
"""

import logging
import socket
import os.path as op
import traceback


import ta_util2.state_store as ss
import ta_util2.job_factory as jf
import ta_util2.utils as utils
import was_consts as c


__all__ = ["HpelJobFactory"]


_LOGGER = logging.getLogger(c.was_log)


class HpelCollectionJob(jf.Job):

    def __init__(self, job_id, config, collector):
        super(HpelCollectionJob, self).__init__(job_id, config)
        self._config = config
        self._collector = collector

    def __call__(self):
        try:
            self._collector.collect_data()
        except Exception:
            _LOGGER.error("Failed to collect data for job=%s, reason=%s",
                          self.ident(), traceback.format_exc())

    def get(self, key, default=None):
        return self._config.get(key, default)


class HpelJobFactory(jf.JobFactory):

    # Fix Cyclic import issue
    import was_hpel_data_loader as hdl

    def __init__(self, job_source, event_writer):
        super(HpelJobFactory, self).__init__(job_source, event_writer)

    def _create_job(self, job):
        appname = utils.get_appname_from_path(op.abspath(__file__))
        job["host"] = job.get("host", socket.gethostname())
        job[c.index] = job.get(c.index, "main")
        job["appname"] = appname
        job[c.event_writer] = self._event_writer
        job[c.state_store] = ss.StateStore(
            job, appname, use_kv_store=job.get("use_kv_store"))
        collector = self.hdl.HpelDataLoader(job)
        return HpelCollectionJob(job[c.log_viewer], job, collector)
