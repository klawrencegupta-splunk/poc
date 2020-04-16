"""
Modular Input for AWS S3
"""
import gc
import sys
import os
import time
import signal
import traceback
import json
import threading

PARENT = os.path.sep+os.path.pardir
FOLDER = os.path.abspath(__file__+PARENT+os.path.sep+'Splunk_TA_f5_bigip')
sys.path.append(FOLDER)
import logger_name
logger_name.logger_name=os.path.basename(__file__)
from Modules.F5Templates import F5TemplatesManager
from Modules.F5Servers import F5ServersManager
from Modules.F5Tasks import F5TasksManager,F5TaskModel
from Modules import to_dict
from f5_bigip_scheduler import F5BigIPScheduler
import logging
from ta_util.log import setup_logger
import ta_util.log
logger = setup_logger(os.path.basename(__file__), level=logging.DEBUG)
from ta_util.log_settings import get_level
from Splunk_TA_f5_bigip.splunklib import modularinput as smi


DEBUGGING_NAME='___debugging___'
MAIN_LOOP_DELAY=40
EXIT_DELAY=30

def env_debugging():
    return DEBUGGING_NAME in os.environ

def task_debugging(task_manager):
    debugging_task=task_manager.get_by_name(DEBUGGING_NAME)
    return not (debugging_task is None or debugging_task.disabled)


class MyScript(smi.Script):


    def get_scheme(self):
        """overloaded splunklib modularinput method"""

        scheme = smi.Scheme("F5 BIG-IP")
        scheme.description = "Pull network traffic data, system logs, system settings, performance metrics, and traffic statistics from the F5 BIG-IP platform."
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = True

        scheme.add_argument(smi.Argument("name", title="Name", description="Name", required_on_create=True))
        scheme.add_argument(smi.Argument("nothing", title="nothing", description="nothing"))
        return scheme


    def validate_input(self, definition):
        pass

    def _exit_handler(self, signum, frame=None):
        logger.log(logging.INFO, "cancellation received.")
        self.exit.set()


    def stream_events(self, inputs, ew):
        """overloaded splunklib modularinput method"""
        try:
            self._stream_events(inputs, ew)
        except Exception as e:
            logger.log(logging.CRITICAL, "Outer Catch All - Traceback:\n"+traceback.format_exc())
            raise Exception(str(e))



    def _stream_events(self, inputs, ew):
        self.exit=threading.Event()
        signal.signal(signal.SIGTERM, self._exit_handler)
        signal.signal(signal.SIGINT, self._exit_handler)

        try:
            level = get_level(os.path.basename(__file__)[:-3],self.service.token)
            logger_name.logger_level = level
            logger.setLevel(level)
        except Exception, exc:
            logger.log(
                logging.ERROR,
                "Cannot get log level. Using default level. - %s" % exc,
                exc_info=1
            )
        logger.log(logging.DEBUG, "stream_events started.")

        token = self.service.token

        event_writer=ew
        server_manager = F5ServersManager(token)
        template_manager = F5TemplatesManager(token)
        task_manager = F5TasksManager(token)

        if task_debugging(task_manager)!=env_debugging():
            exit(0)

        schedulers = {}

        logger.log(logging.DEBUG, "Tasks loaded.")
        while True:
            try:
                server_manager.reload()
                template_manager.reload()
                task_manager.reload()

                logger.log(logging.DEBUG, "Main loop start.")
                servers = to_dict(server_manager.all(), ':')
                templates = to_dict(template_manager.all(), ':')
                tasks = [task for task in task_manager.all()]
                new_schedulers = {}
            except Exception as e:
                time.sleep(MAIN_LOOP_DELAY)
                if self.exit.isSet():
                    break
                logger.log(logging.ERROR, "Error in getting task definitions by restful API(maybe splunk daemon is down?) - Traceback:\n"+traceback.format_exc())
                continue

            for task in tasks:
                if self.exit.isSet():
                    break

                if isinstance(task, F5TaskModel):
                    if task.name==DEBUGGING_NAME:
                        continue
                    logger.log(logging.DEBUG, "Task %s"%task.name)
                    t_hash = task.get_hash()
                    if task.disabled:
                        if t_hash in schedulers:
                            schedulers[t_hash].stop.set()
                            del schedulers[t_hash]
                    else:
                        if t_hash in schedulers:
                            scheduler = schedulers[t_hash]
                            scheduler.update(servers, templates, task)
                            new_schedulers[t_hash] = scheduler
                            del schedulers[t_hash]
                        else:
                            new_schedulers[t_hash] = F5BigIPScheduler(servers, templates, task, event_writer)
                            new_schedulers[t_hash].start()
            for scheduler in schedulers.values():
                scheduler.stop.set()

            schedulers = new_schedulers

            if self.exit.isSet():
                break
            gc.collect()
            time.sleep(MAIN_LOOP_DELAY)

        # exit

        for scheduler in schedulers.values():
            scheduler.stop.set()
        time.sleep(EXIT_DELAY)


if __name__ == "__main__":

    exitcode = MyScript().run(sys.argv)
    sys.exit(exitcode)
