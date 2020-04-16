

from threading import Condition
import logging

from bigsuds import BIGIP

import logger_name
logger=logging.getLogger(logger_name.logger_name)
logger.setLevel(logger_name.logger_level)


class F5_BigIP_Host(object):
    
    def __init__(self, maxCount):
        self._maxCount = maxCount
        self._conns = []
        self._count = 0
    
    def count(self):
        return self._count
    
    def minus(self):
        self ._count = 0 if self._count<=0 else self._count-1
    
    def new(self, hostname, username, password):
        self._count = self._count+1
        return BIGIP(hostname=hostname, username=username, password=password)
    
    def get(self, hostname, username, password):
        return self._conns.pop() if self._conns else self.new(hostname, username, password)
    
    def put(self, conn):
        self._conns.append(conn)
        
    def has(self):
        return self._conns or self._count<self._maxCount


class F5_BigIP_Pool(object):
    
    cond = Condition()
    pool = {}
    maxCount = 1
    
    @classmethod
    def getConn(cls, hostname, username, password):
        logger.log(logging.DEBUG, "Get an f5 connection: {username}@{hostname}".format(hostname=hostname, username=username))
        cls.cond.acquire()
        if hostname not in cls.pool:
            cls.pool[hostname] = F5_BigIP_Host(cls.maxCount)
        logger.log(logging.DEBUG, 'F5 connection count for "{username}@{hostname}" is {count}'.format(hostname=hostname, username=username, count=cls.pool[hostname].count()))
        while True:
            if cls.pool[hostname].has():
                conn = cls.pool[hostname].get(hostname=hostname, username=username, password=password)
                break
            logger.log(logging.DEBUG, "Wait for an f5 connection: {username}@{hostname}".format(hostname=hostname, username=username))
            cls.cond.wait()
            logger.log(logging.DEBUG, "Wake for an f5 connection: {username}@{hostname}".format(hostname=hostname, username=username))
        logger.log(logging.DEBUG, 'F5 connection count for "{username}@{hostname}" is {count}'.format(hostname=hostname, username=username, count=cls.pool[hostname].count()))
        cls.cond.release()
        return conn
    
    @classmethod
    def putConn(cls, hostname, username, bigip):
        logger.log(logging.DEBUG, "Put an f5 connection: {username}@{hostname}".format(hostname=hostname, username=username))
        logger.log(logging.DEBUG, 'F5 connection count for "{username}@{hostname}" is {count}'.format(hostname=hostname, username=username, count=cls.pool[hostname].count()))
        cls.cond.acquire()
        cls.pool[hostname].put(bigip)
        cls.cond.notify(2)
        cls.cond.release()
    
    @classmethod
    def delConn(cls, hostname, username):
        logger.log(logging.DEBUG, "Drop an f5 connection: {username}@{hostname}".format(hostname=hostname, username=username))
        logger.log(logging.DEBUG, 'F5 connection count for "{username}@{hostname}" is {count}'.format(hostname=hostname, username=username, count=cls.pool[hostname].count()))
        cls.cond.acquire()
        cls.pool[hostname].minus()
        cls.cond.notify(2)
        cls.cond.release()
