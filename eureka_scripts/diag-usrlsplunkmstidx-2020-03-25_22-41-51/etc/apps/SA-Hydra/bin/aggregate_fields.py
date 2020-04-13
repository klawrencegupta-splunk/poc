# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.

import sys
import splunk.Intersplunk as si
import logging, logging.handlers
import os
import re


class Usage(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class FieldAggregator(object):
    """
    This class performs the operations for aggregating all fields that match a
    pattern into a new field
    """

    def __init__(self, term, term_re):
        self.new_field_name = "aggregated_" + term
        self.re = term_re

    def aggregate_fields(self, row):
        """
        Take a row and aggregate stuff that matches the aggregator's pattern.
        returns a tuple of the name of the new field and it's value
        ARGS:
            row - a splunk result row (dict of field_name -> value)

        RETURNS a tuple of new field name and value
        """
        tmp = []
        for key, value in row.iteritems():
            if self.re.search(key):
                tmp.append(key + ": " + value)
        tmp.sort()
        return self.new_field_name, tmp


def setup_logger():
    """
    Setup a logger for the search command
    """

    logger = logging.getLogger('aggregatefields')
    logger.setLevel(logging.DEBUG)

    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(os.environ['SPLUNK_HOME'], "var", "log", "splunk", "aggregate_fields.log"))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


if __name__ == '__main__':
    try:
        (isgetinfo, sys.argv) = si.isGetInfo(sys.argv)
        if isgetinfo:
            #outputInfo(streaming, generating, retevs, reqsop, preop, timeorder=False):
            si.outputInfo(True, False, True, False, None, False)
            sys.exit(0)

        results, dummyresults, settings = si.getOrganizedResults()
        logger = setup_logger()

        if len(sys.argv) < 2:
            raise Usage("aggregate_fields requires at least 1 arg, number passed=" + str(len(sys.argv) - 1))

        terms = sys.argv[1:]
        aggregators = []
        for term in terms:
            term_re = None
            term = term.strip(" ,")
            if term.startswith("*") and term.endswith("*"):
                term = re.escape(term.strip("*"))
                term_re = re.compile(term)
            elif term.startswith("*"):
                term = re.escape(term.strip("*"))
                term_re = re.compile(term + "$")
            elif term.endswith("*"):
                term = re.escape(term.strip("*"))
                term_re = re.compile("^" + term)
            else:
                raise Usage(
                    "Could not detect wildcard on either side of term={0}, must supply terms with wildcards".format(
                        term))
            aggregators.append(FieldAggregator(term, term_re))

        for r in results:
            new_fields = []
            for aggregator in aggregators:
                new_fields.append(aggregator.aggregate_fields(r))
            for new_field_name, new_field_data in new_fields:
                r[new_field_name] = new_field_data

        si.outputResults(results)

    except Usage as e:
        results = si.generateErrorResults("%s Usage: | aggregate_field *_interval *_expiration..." % e)
        si.outputResults(results)

    except Exception as e:
        logger.exception("Error in aggregate_fields: %s", e)
        results = si.generateErrorResults(
            "Error in aggregate_fields, see aggregate_fields.log for more info: %s" % str(e))
        si.outputResults(results)
