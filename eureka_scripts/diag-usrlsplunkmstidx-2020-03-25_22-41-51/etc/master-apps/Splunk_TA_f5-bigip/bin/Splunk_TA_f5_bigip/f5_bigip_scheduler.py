from taskgen.task import IntervalTask
from taskgen.generator import TaskGenerator, passiveServerData2tasks
import threading
import json
import datetime
from splunklib.modularinput.event import Event
import traceback
import logging
import logger_name
import gc
import ta_util.log
import time
logger=logging.getLogger(logger_name.logger_name)
class F5BigIPIntervalTask(IntervalTask):

    RUN_QUEUE_STATE={
        (False,False):'wait',
        (True,False):'run',
        (True,True):'queue',
        (False,True):'invalid',
    }


    def __init__(self, interval, queries=[],next_exec_time=None):
        IntervalTask.__init__(self, interval, queries,next_exec_time)
        self.rs_lock = threading.Lock()
        self.running = False
        self.queueing = False

    def start(self):
        with self.rs_lock:
            ret=not self.running
            self.queueing = self.running
            self.running = True
            return ret

    def end(self):
        with self.rs_lock:
            self.running = self.queueing
            self.queueing=False
            ret=not self.running
            return ret

    def terminate(self):
        with self.rs_lock:
            self.running = False
            self.queueing = False
            return True




class F5BigIPPassiveServerData(object):
    def __init__(self, url, partitions, username, password, interval, template, global_interval):
        self.url = url
        self.username = username
        self.password = password
        self.template=template
        self.server_interval=interval
        self.global_interval = global_interval
        self.interval= int(interval) if interval else global_interval
        self.tasks = []
        from F5_iControl import F5_iControl
        task_dict = F5_iControl(url, partitions, username, password).getTemplates(template)
        if 0 in task_dict:
            if not self.interval in task_dict:
                task_dict[self.interval] = []
            task_dict[self.interval].extend(task_dict[0])
            del task_dict[0]
        self.tasks = [F5BigIPIntervalTask(key, queries=task_dict[key]) for key in task_dict]

    def get_hash(self):
        return hash((self.url,self.username,self.password,self.server_interval,self.template))

class F5BigIPPassiveServerLoader(object):
    def __init__(self, server_models, template_models, global_interval):
        self.hashcode = 0
        self.template = None
        self.servers = None
        self.global_interval = 0
        self.server_data_list = None
        self._lock = threading.Lock()
        self.update(server_models, template_models, global_interval)

    def get_hash(self):
        return hash((self.template, self.global_interval, tuple(self.servers)))

    def refresh(self):
        server_data_list=[]
        for (url, partitions, username, password, interval) in self.servers:
            try:
                server_data_list.append(F5BigIPPassiveServerData(url, partitions, username, password, interval, self.template, self.global_interval))
            except Exception as e:
                logger.log(logging.ERROR, ("failed to add server data with url:%s - Traceback:\n"%url)+traceback.format_exc())

        self._lock.acquire()
        self.server_data_list = server_data_list
        self._lock.release()

    def update(self, server_models, template_models, global_interval):
        self.template = '\n'.join([t.content for t in template_models])
        self.servers = [(server.f5_bigip_url, server.f5_bigip_partitions, server.account_name, server.account_password, server.interval) for server in server_models]
        self.global_interval = global_interval
        hashcode = self.get_hash()
        if hashcode != self.hashcode:
            self.refresh()
            self.hashcode = hashcode

    def load(self):
        self._lock.acquire()
        ret = self.server_data_list
        self._lock.release()
        return ret


class F5BigIPScheduler(threading.Thread):
    def __init__(self, servers, templates, task, event_writer):
        threading.Thread.__init__(self)
        self.metadata = task.get_metadata()
        self.global_interval = 0
        self.server_loader = None
        self.update(servers, templates, task)
        self.stop = threading.Event()
        self.event_writer=event_writer

    def update(self, servers, templates, task):
        server_models = [servers[key] for key in task.get_server_keys()]
        template_models = [templates[key] for key in task.get_template_keys()]
        self.global_interval = int(task.interval)
        if self.server_loader:
            self.server_loader.update(server_models, template_models, self.global_interval)
        else:
            self.server_loader = F5BigIPPassiveServerLoader(server_models, template_models, self.global_interval)

    def run(self):
        try:
            task_generator = TaskGenerator(self.metadata, self.global_interval, self.server_loader, passiveServerData2tasks, logger=logger)
            for (task, server) in task_generator:
                logger.log(logging.DEBUG,'new work generated, server: %s',server.server_data.url )
                if self.stop.isSet():
                    break
                if task.start():
                    F5BigIPWorker(task, server, self.event_writer, self.stop).start()
                    logger.log(logging.DEBUG,'worker started, server: %s',server.server_data.url )
                logger.log(logging.DEBUG,'start to generete new work')
        except Exception as e:
            logger.log(logging.ERROR, "Error in F5BigIPScheduler.run() - Traceback:\n"+traceback.format_exc())



class F5BigIPWorker(threading.Thread):
    def __init__(self, task, server, event_writer, stop_event):
        threading.Thread.__init__(self)
        self.task = task
        self.server = server
        self.stop = stop_event
        self.event_writer=event_writer

    def run(self):
        try:
            while True:
                for query in self.task.queries:
                    if self.server.to_be_deleted or self.stop.isSet():
                        self.task.terminate()
                        break
                    logger.log(logging.DEBUG,'start fetch, server: %s',self.server.server_data.url)
                    items=query.fetch()
                    logger.log(logging.DEBUG,'end fetch.')
                    if items:
                        timestamp = int(time.time())
                        for item in items:
                            self.json_event(item,timestamp)
                if self.task.end():
                    break
            logger.log(logging.DEBUG,'worker exit.')
        except Exception as e:
            logger.log(logging.ERROR, "Error in F5BigIPWorker.run() - Traceback:\n"+traceback.format_exc())
            self.task.terminate()


    def json_event(self,item,timestamp):
        logger.log(logging.DEBUG,'start index.')
        data=json.dumps(item)
        index=self.server.metadata['index']
        sourcetype=self.server.metadata['sourcetype']
        source=self.server.server_data.url
        event=Event(data=data, time=timestamp,  index=index, host=source, source=source, sourcetype=sourcetype)
        self.event_writer.write_event(event)
        logger.log(logging.DEBUG,'end index.')
