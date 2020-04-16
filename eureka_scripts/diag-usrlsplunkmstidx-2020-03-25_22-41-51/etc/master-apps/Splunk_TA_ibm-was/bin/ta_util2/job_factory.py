import time

from ta_util2.timer import Timer


class JobFactory(object):

    def __init__(self, job_source, event_writer):
        self._job_source = job_source
        self._event_writer = event_writer

    def start(self):
        self._job_source.start()

    def tear_down(self):
        self._job_source.tear_down()

    def get_jobs(self):
        """
        Get jobs from job source
        """

        jobs = self._job_source.get_jobs(timeout=1)
        if jobs:
            return [self._create_job(job) for job in jobs]
        return None

    def _create_job(self, job):
        """
        @job: dict for job definition
        """

        raise NotImplementedError("Derived class shall override _create_job")


class Job(Timer):

    def __init__(self, job_id, config, when=None):
        """
        @job_id: a unique job_id, if it is None, an unique job id will be
                 assinged automatically
        @config: dict like object, contains job properties
        @when: the first time the job is executed, default is now
        """

        if when is None:
            when = time.time()
        interval = config.get("duration", 0)
        super(Job, self).__init__(self, when, interval, job_id)
        self._config = config

    def __call__(self):
        pass

    def is_alive(self):
        return True

    def get(self, key, default=None):
        return self._config.get(key, default)
