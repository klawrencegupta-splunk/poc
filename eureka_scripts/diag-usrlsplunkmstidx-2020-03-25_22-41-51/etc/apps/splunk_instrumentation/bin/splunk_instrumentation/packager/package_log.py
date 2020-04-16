
from splunk_instrumentation.constants import *
import os
import time
from datetime import date, timedelta

class PackageLog(object):

    def get_last_send(self):
        last_send = self._last_read_time()
        if (not last_send):
            return None
        return {"end_timestamp" : last_send, "start_timestamp" : 0, "success" : True}

    def start_send(self, id, start, stop):
        return True

    def finish_send(self, id, start, stop):
        self._set_last_read_time(stop)

    def _last_read_time(self):
        if os.path.isfile(LAST_READ_TIME_FILE):
            return open(LAST_READ_TIME_FILE, 'r').read().strip()
        else:
            return None

    def _set_last_read_time(self, time):
        f = open(LAST_READ_TIME_FILE, 'w')
        f.write(str(time) + '\n')
        f.close()

    def current_time(self):
        return self._format_time_for_splunk(time.gmtime())

    def yesterday_time(self):

        today = date.today()
        yesterday = (today - timedelta(1)).timetuple()
        return self._format_time_for_splunk(yesterday)

    def _format_time_for_splunk(self, seconds):
        return ('%d/%d/%d:%d:%d:%d' % (
            seconds.tm_mon,
            seconds.tm_mday,
            seconds.tm_year,
            seconds.tm_hour,
            seconds.tm_min,
            seconds.tm_sec))