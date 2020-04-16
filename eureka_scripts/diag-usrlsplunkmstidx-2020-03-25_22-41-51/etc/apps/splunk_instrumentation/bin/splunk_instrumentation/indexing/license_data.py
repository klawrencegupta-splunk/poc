import logging

logger = logging.getLogger(__name__)

import json, sys, os

from base_class import BaseClass
from splunk_instrumentation.constants import *



def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, date):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


class LicenseData(BaseClass):
    def __init__(self, splunkrc=None, index_name=INSTRUMENTATION_INDEX_NAME,spl = None):
        super(LicenseData, self).__init__(splunkrc=splunkrc)
        self.spl = spl
        self._set_index(index_name)

    def process_new_events(self,start,stop):
        search_cmd = 'search index=' + self.index_name
        search_cmd += " sourcetype=" + INSTRUMENTATION_SOURCETYPE + " | spath date | search "
        if t_start:
            search_cmd += (' date>=%s' % t_start.strftime("%Y-%m-%d"))
        if t_end:
            search_cmd += (' date<=%s' % t_end.strftime("%Y-%m-%d"))

        visibility_cmd = self._get_visibility_cmd(visibility)
        search_cmd += " (%s)" % visibility_cmd

        return self._query(search_cmd)

