from hydra import HydraHandler
import time
import random


class ExampleBigJobHandler(HydraHandler):
    """
    This class provides no value except as an example implementation of a hydra worker.
    Handles a big scary job.
    """

    def run(self, session, config, create_time, last_time):
        """
        This is the method you must implement to perform your atomic task, in this case a "big job"
        args:
            session - the session object return by the loginToTarget method
            config - the dictionary of all the config keys from your stanza in the collection.conf
            create_time - the time this task was created/scheduled to run (datetime object)
            last_time - the last time this task was created/scheduler to run (datetime object)

        RETURNS True if successful, False otherwise
        """
        try:
            msg = "worker=" + session["worker"] + " from node=" + session["node"] + " says " + config['message']
            # oh no this big job is going to take some time to finish
            time.sleep(random.random() * 30.0)
            self.output.sendData(msg, sourcetype="hydra_example_data", source="big_job", host=session['target'])
            return True
        except Exception as e:
            self.logger.exception(e)
            return False


class ExampleMediumJobHandler(HydraHandler):
    """
    This class provides no value except as an example implementation of a hydra worker.
    Handles a medium job.
    """

    def run(self, session, config, create_time, last_time):
        """
        This is the method you must implement to perform your atomic task, in this case a "big job"
        args:
            session - the session object return by the loginToTarget method
            config - the dictionary of all the config keys from your stanza in the collection.conf
            create_time - the time this task was created/scheduled to run (datetime object)
            last_time - the last time this task was created/scheduler to run (datetime object)

        RETURNS True if successful, False otherwise
        """
        try:
            msg = "worker=" + session["worker"] + " from node=" + session["node"] + " says " + config['message']
            # oh no this medium job is going to take time to finish
            time.sleep(random.random() * 10.0)
            self.output.sendData(msg, sourcetype="hydra_example_data", source="medium_job", host=session['target'])
            return True
        except Exception as e:
            self.logger.exception(e)
            return False


class ExampleSmallJobHandler(HydraHandler):
    """
    This class provides no value except as an example implementation of a hydra worker.
    Handles a small job.
    """

    def run(self, session, config, create_time, last_time):
        """
        This is the method you must implement to perform your atomic task, in this case a "big job"
        args:
            session - the session object return by the loginToTarget method
            config - the dictionary of all the config keys from your stanza in the collection.conf
            create_time - the time this task was created/scheduled to run (datetime object)
            last_time - the last time this task was created/scheduler to run (datetime object)

        RETURNS True if successful, False otherwise
        """
        try:
            msg = "worker=" + session["worker"] + " from node=" + session["node"] + " says " + config['message']
            # oh this small job is going to take no time at all to finish
            time.sleep(random.random() * 5.0)
            self.output.sendData(msg, sourcetype="hydra_example_data", source="small_job", host=session['target'])
            return True
        except Exception as e:
            self.logger.exception(e)
            return False