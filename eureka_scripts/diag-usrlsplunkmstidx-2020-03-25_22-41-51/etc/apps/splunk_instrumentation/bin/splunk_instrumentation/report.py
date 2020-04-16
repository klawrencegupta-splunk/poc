import json
import os
from constants import INST_MODE
import time
from datetime_util import date_to_timestamp, json_serial, utcNow


class Report(object):
    def __init__(self):
        self.log = {}

    def report(self, name, value, start=None):
        arrayTest = name.split("[")
        name = arrayTest[0]
        arrayTest = len(arrayTest) == 2

        def nested_set(dic, path, value):
            keys = path.split(".")
            for key in keys[:-1]:
                dic = dic.setdefault(key, {})

            if arrayTest:
                dic.setdefault(keys[-1], [])
                dic[keys[-1]].append(value)
            else:
                dic[keys[-1]] = value

        if start and isinstance(value, dict):
            value['time'] = self.start_profiling() - start
        nested_set(self.log, name, value)
        if not INST_MODE == "INPUT":
            print "report::" + name + '=' + json.dumps(value, default=json_serial)
        return value

    def start_profiling(self):
        return time.time()

    def send(self):
        self.log.setdefault('timestamp', date_to_timestamp(utcNow()))
        print json.dumps(self.log, default=json_serial)

    def get(self, path):
        keys = path.split(".")
        dic = self.log
        for key in keys:
            dic = dic.setdefault(key, {})
        return dic

    def write(self):
        self.log.setdefault('timestamp', date_to_timestamp(utcNow()))
        with open(os.path.dirname(
                os.path.realpath(__file__)) + '/report.json', 'w') as target:
            target.write(json.dumps(self.log, default=json_serial))


report = Report()
