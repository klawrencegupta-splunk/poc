import heapq
from collections import deque
from task import ServerTask
import sys

class ServerQueue(object):
    def __init__(self):
        self.heap = []
        self.queue = deque()


    def clear(self):
        self.heap = []
        self.queue.clear()

    def size(self):
        return len(self)

    def __len__(self):
        return len(self.heap) + len(self.queue)


    def empty(self):
        return len(self) == 0

    def push_server(self, server):
        if not isinstance(server, ServerTask):
            raise TypeError('Wrong type "%s"; only ServerTask object can be pushed' % str(type(server)))

        if (server.multi_interval):
            heapq.heappush(self.heap, server)
            #print >>sys.stderr, 'in ', str(server)
        else:
            self.queue.append(server)


    def heap_top(self):
        return self.heap[0] if len(self.heap) > 0 else None

    def queue_top(self):
        return self.queue[0] if len(self.queue) > 0 else None

    def top_server(self):
        self.trim()
        th = self.heap_top()
        tq = self.queue_top()
        if th is None:
            return tq
        if tq is None:
            return th
        return th if th < tq else tq

    def pop_server(self):
        self.trim()
        th = self.heap_top()
        tq = self.queue_top()
        if th is None:
            return self.queue.popleft()
        if tq is None:
            #print >>sys.stderr, 'out', str(self.heap[0])
            return heapq.heappop(self.heap)
        if th < tq:
            #print >>sys.stderr, 'out', str(self.heap[0])
            return heapq.heappop(self.heap)
        else:
            return self.queue.popleft()

    def trim(self):
        while len(self.heap) > 0 and self.heap[0].to_be_deleted:
            heapq.heappop(self.heap)
        while len(self.queue) > 0 and self.queue[0].to_be_deleted:
            self.queue.popleft()

    def close_all(self):
        for ts in self.heap:
            ts.close()
        for ts in self.queue:
            ts.close()
        self.clear()