import threading
from time import time
import random
import logging

import ta_util2.log_files as log_files


_LOGGER = logging.getLogger(log_files.ta_util)


class Scheduler(object):
    """
    A simple scheduler which schedules the periodic or once event
    """

    import ta_util2.sortedcontainers as sc

    max_delay_time = 60

    def __init__(self):
        self._jobs = Scheduler.sc.SortedSet()
        self._lock = threading.Lock()

    def get_ready_jobs(self):
        """
        @return: a 2 element tuple. The first element is the next ready
                 duration. The second element is ready jobs list
        """

        now = time()
        ready_jobs = []
        sleep_time = 1

        with self._lock:
            job_set = self._jobs
            total_jobs = len(job_set)
            for job in job_set:
                if job.get_expiration() <= now:
                    if job.is_alive():
                        ready_jobs.append(job)
                    else:
                        _LOGGER.warn("Removing dead job=%s", job.get("name"))

            if ready_jobs:
                del job_set[:len(ready_jobs)]

            for job in ready_jobs:
                if job.get_interval() != 0:
                    # repeated job, calculate next due time and enqueue
                    job.update_expiration()
                    job_set.add(job)

            if job_set:
                sleep_time = job_set[0].get_expiration() - now
                sleep_time = sleep_time if sleep_time > 0 else 0.1

        if ready_jobs:
            _LOGGER.info("Get %d ready jobs, next duration is %f, "
                         "and there are %s jobs scheduling",
                         len(ready_jobs), sleep_time, total_jobs)

        ready_jobs.sort(key=lambda job: job.get("priority", 0), reverse=True)
        return (sleep_time, ready_jobs)

    def add_jobs(self, jobs):
        with self._lock:
            now = time()
            job_set = self._jobs
            for job in jobs:
                delay_time = random.randrange(0, self.max_delay_time)
                job.set_initial_due_time(now + delay_time)
                job_set.add(job)

    def update_jobs(self, jobs):
        with self._lock:
            job_set = self._jobs
            for njob in jobs:
                job_set.discard(njob)
                job_set.add(njob)

    def remove_jobs(self, jobs):
        with self._lock:
            job_set = self._jobs
            for njob in jobs:
                job_set.discard(njob)

    def number_of_jobs(self):
        with self._lock:
            return len(self._jobs)
