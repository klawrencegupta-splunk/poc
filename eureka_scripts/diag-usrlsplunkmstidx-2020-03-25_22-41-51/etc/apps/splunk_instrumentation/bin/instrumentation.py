# scripted inputs entry point

import os
import sys
import argparse
import datetime
import splunk_instrumentation.datetime_util as datetime_util
from time import sleep

'''
This must happen before splunk_instrumentation.constants is imported.
'''
parser = argparse.ArgumentParser()
parser.add_argument('--scheme', action='store_true')
parser.add_argument('-v', '--validate-arguments', action='store_true')
parser.add_argument('--no-collect', action='store_true', help='will not collect and index data')
parser.add_argument('--no-send', action='store_true', help='will not query _telemetry and send data')
parser.add_argument('-m', '--mode', default="INPUT", help='is required if not running from splund modular inputs')
parser.add_argument('--test-schema')
parser.add_argument('--log-level')
parser.add_argument('--execution-id')
parser.add_argument('--quickdraw-url', help='used to override the quickdraw-url')
parser.add_argument('--default-quickdraw', help='used to override the quickdraw-url response')
parser.add_argument('--start-date', help='first date to query, in YYYY-MM-DD format (defaults to yesterday)')
parser.add_argument('--stop-date', help='last date to query, in YYY-MM-DD format (inclusive) (defaults to yesterday)')
args = parser.parse_args()


# configuration is done through environmental variables. Convert command line to environmental.

if args.mode:
    os.environ['INST_MODE'] = args.mode
if args.no_collect:
    os.environ['INST_NO_COLLECT'] = args.no_collect
if args.no_send:
    os.environ['INST_NO_SEND'] = args.no_send
if args.test_schema:
    os.environ['INST_TEST_SCHEMA'] = args.test_schema
if args.log_level:
    os.environ['INST_DEBUG_LEVEL'] = args.log_level
if args.execution_id:
    os.environ['INST_EXECUTION_ID'] = args.execution_id
if args.quickdraw_url:
    os.environ['QUICKDRAW_URL'] = args.quickdraw_url
if args.default_quickdraw:
    os.environ['DEFAULT_QUICKDRAW'] = args.default_quickdraw


# Routine to get the value of an input token
def get_key():
    # read everything from stdin
    config_str = sys.stdin.read()
    # stdin is just a token
    os.environ['INST_TOKEN'] = config_str.rstrip()


# the default mode is INPUT and is what scripted inputs uses and implies
# there is a token passed in to stdin.
if os.environ['INST_MODE'] == "INPUT":
    get_key()

# these imports inlude splunk_instrumentation.constants which need to be imported after environmental vars are set
from splunk_instrumentation.constants import SPLUNKRC, INST_PRE_EXECUTE_SLEEP, SPLUNKD_URI   # noqa: E402
from splunk_instrumentation.service_bundle import ServiceBundle  # noqa: E402
from splunk_instrumentation.splunkd import Splunkd  # noqa: E402
from splunk_instrumentation.input import run_input  # noqa: E402


def normalize_date_range_params(args, report_start_date):
    '''
    Normalizes date range used for Data collection.
    Start date for Data collection could be args.start_date, reportStartDate or yesterday
    End data for Data collection could be args.stop_date or yesterday
    :param args: List of arguments provided through CLI
    :param report_start_date: reportStartDate specified in telemetry.conf
    :return:
    '''
    yesterday = datetime.date.today() - datetime.timedelta(days=1)

    args.start_date = datetime_util.str_to_date(args.start_date) if args.start_date\
        else datetime_util.str_to_date(report_start_date) if report_start_date else yesterday

    args.stop_date = datetime_util.str_to_date(args.stop_date) if args.stop_date else yesterday


def validate_date_range(args):
    if args.stop_date < args.start_date:
        raise Exception("Start date must be <= stop date")


def should_input_run(telemetry_conf_service):
    '''
    Compares current time with the scheduledDay and scheduledHour
    to determine whether Input should execute or not
    :param telemetry_conf_service: Service for telemetry.conf
    :return: True if current time matched scheduling in telemetry.conf
    '''
    scheduled_day = telemetry_conf_service.content.get('scheduledDay')
    scheduled_hour = telemetry_conf_service.content.get('scheduledHour')
    # Compare day and hour to time now
    now = datetime.datetime.now()

    if ((scheduled_day == '*' or scheduled_day == str(now.weekday())) and
            (scheduled_hour == str(now.hour))):
        return True
    return False


def process_input_params(telemetry_conf_service, args):
    '''
    Processes Input date range params and sets reportStartDate in telemetery.conf
    :param telemetry_conf_service: Service for telemetry.conf
    :param args: List of arguments passed to Scripted input
    :return:
    '''
    report_start_date = telemetry_conf_service.content.get('reportStartDate')
    normalize_date_range_params(args, report_start_date)
    validate_date_range(args)

    # update the reportStartDate before triggering input.py
    telemetry_conf_service.update({
        'reportStartDate': args.stop_date
    })


# Routine to index data
def main():
    sleep(INST_PRE_EXECUTE_SLEEP)
    if os.environ['INST_MODE'] == "DEV":
        splunkd = Splunkd(**SPLUNKRC)
    else:
        splunkd = Splunkd(token=os.environ['INST_TOKEN'], server_uri=SPLUNKD_URI)

    services = ServiceBundle(splunkd)
    telemetry_conf_service = services.telemetry_conf_service

    if should_input_run(telemetry_conf_service):
        process_input_params(telemetry_conf_service, args)
        run_input({'start': args.start_date, 'stop': args.stop_date})
    else:
        # indicate to caller that input wasn't executed
        sys.exit(114)


# Script must implement these args: scheme, validate-arguments
main()

sys.exit(0)
