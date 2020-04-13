import sys
import socket
from hydra.hydra_worker import HydraWorker
import example_handlers


class ExampleHydraWorker(HydraWorker):
    title = "Example Hydra Worker"
    description = "Example implementation of a worker that performs distributed work"
    handlers = {
    "big_job": example_handlers.ExampleBigJobHandler,
    "medium_job": example_handlers.ExampleMediumJobHandler,
    "small_job": example_handlers.ExampleSmallJobHandler
    }
    app = "SA-Hydra"

    def loginToTarget(self, target, user, password):
        """
        Normally here is where you'd log into a target, for this example we'll just log and return a dict
        args:
            target - the uri to the domain specific asset we need to log in to
            user - the user name stored in splunkd associated with that target
            password - the password stored in splunkd associated with that target
        RETURNS a dict containing the login information
        """
        session = {
        "target": target,
        "user": user,
        "password": password,
        "worker": self.worker_name_full,
        "node": socket.gethostname()
        }
        self.logger.debug("Fake logging into target, will return dict: {0}".format(str(session)))
        return session

    def isSessionValid(self, session):
        """
        For our example case we will just check that it is not None
        args:
            session - the python object returned by loginToTarget to be tested

        RETURNS True if session is valid, False if it must be refreshed
        """
        if session is not None:
            self.logger.debug("Session is not None and thus valid")
            return True
        else:
            self.logger.debug("Session is None and thus must be remade")
            return False


if __name__ == '__main__':
    worker = ExampleHydraWorker()
    worker.execute()
    sys.exit(0)