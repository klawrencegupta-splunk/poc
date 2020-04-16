from data_point import DataPoint
from data_point import registerDataPoint


class MockDataPoint(DataPoint):
    def __init__(self, dataPointSchema, options={}):
        super(MockDataPoint, self).__init__(dataPointSchema, options)

    def collect(self):
        return self.dataPointSchema.dataPointSchema['results']


registerDataPoint(MockDataPoint)
