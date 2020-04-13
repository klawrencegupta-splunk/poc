from task import ServerTask
from serverqueue import ServerQueue
from datetime import datetime, timedelta
import time
import logging
import traceback

class stanza(dict):
    def __init__(self,app_name,name):
        self.app_name=app_name
        self.name=name

    def hash(self):
        return hash(self.app_name,self.name,tuple(sorted(self.items())))

class TaskGenerator(object):
    LOAD_INTERVAL = 60;

    def __init__(self, metadata, global_interval, server_loader, server2tasks, ServerTaskClass=ServerTask, logger=None, **kwargs):
        if not issubclass(ServerTaskClass,ServerTask):
            raise TypeError("ServerTaskClass must extend ServerTask")
        self.logger=logger
        self.metadata = metadata
        self.server_map = {}
        self.server_queue = ServerQueue()
        self.server_loader = server_loader
        self.server2tasks = server2tasks
        self.global_interval = global_interval
        self.ServerTaskClass = ServerTaskClass

    def close_all(self):
        self.server_queue.close_all()
        self.server_map.clear()


    def __iter__(self):
        last_load = datetime(1970, 1, 1)
        while True:
            now = datetime.now()
            if (now - last_load).total_seconds() > TaskGenerator.LOAD_INTERVAL:
                try:
                    server_data_list = self.server_loader.load()
                    if not server_data_list and not self.server_queue.empty():
                        self.close_all()
                    else:
                        self.refresh_servers(server_data_list)
                except Exception as e:
                    last_load = now
                    if self.logger:
                        self.logger.log(logging.ERROR, "Refreshing servers error - Traceback:\n"+traceback.format_exc())
                    continue
                last_load = now

            self.server_queue.trim()
            if self.server_queue.empty():
                time.sleep(1)
                continue

            server = self.server_queue.pop_server()
            server.wait()

            task = server.next_task()
            self.server_queue.push_server(server)
            yield (task, server)

    def refresh_servers(self, server_data_list):
        temp_map = {}
        for server_data in server_data_list:
            temp_map[server_data.get_hash()] = server_data
        keys = self.server_map.keys()
        for key in keys:
            if not key in temp_map:
                self.server_map[key].to_be_deleted = True
                del self.server_map[key]
        for key in temp_map:
            if not key in self.server_map:
                temp = self.ServerTaskClass(temp_map[key], self.metadata, self.global_interval,
                                            self.server2tasks(temp_map[key]))
                self.server_map[key] = temp
                self.server_queue.push_server(temp)


class StanzaServerLoader(object):
    def __init__(self, stanza):
        self.stanza=stanza

    def load(self):
        return []



class PassiveServerData(object):
    def __init__(self,server_info,tasks):
        self.info=server_info
        self.tasks=tasks

    def _hash(self): # to be overloaded
        return 0

def passiveServerData2tasks(psd):
    return psd.tasks

