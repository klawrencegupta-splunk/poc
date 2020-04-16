import os, splunk.Intersplunk, logging, sys
from splunk.clilib import cli_common as cli
import splunk.entity as en
import subprocess

###
# | pxgremediate xgridAction=quarantine xgridType=ip xgridTarget="10.0.0.15"
###

def logger(fname):
    try:
        LEVELS = {'DEBUG': logging.DEBUG,
                  'INFO': logging.INFO,
                  'WARNING': logging.WARNING,
                  'ERROR': logging.ERROR,
                  'CRITICAL': logging.CRITICAL}
        appConf = cli.getConfStanza('loglevel','logging')
        logLevelConf = appConf['pxgremediate_log_level']
        logLevel = LEVELS.get(logLevelConf)
        logger = logging.getLogger()
        logger.setLevel(logLevel)
        logfilename = os.path.join(os.environ['SPLUNK_HOME'],'var','log','splunk',fname)
        logfile = logging.StreamHandler(open(logfilename, "a"))
        logfile.setLevel(logLevel)
        logfile.setFormatter(logging.Formatter('%(asctime)s [%(process)06d] %(levelname)-8s %(name)s:  %(message)s'))
        logger.addHandler(logfile)
        logger.info("Logger Initialized")
        logger.info(''.join(['Log level read in from loglevel.conf file: ',str(logLevel)]))
        logger.info("CRITICAL=50, ERROR=40, WARNING=30, INFO=20, DEBUG=10, NOTSET=0")
    except Exception, e:
        raise Exception("Could not open logger for file %s at path %s. Error: %s"
                      % (fname, logfilename, str(e)))
    return logger

def pxgremediate():
    try:
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()

        results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

        # acquire the env items for debugging
        user_id = options.get('fieldname', 'search_user')
        logger.debug(''.join(['user_id=',user_id]))

        owner = settings.get("owner", None)
        logger.debug(''.join(['owner=',str(owner)]))

        sessionKey = settings.get("sessionKey", None)
        logger.debug(''.join(['sessionKey=',str(sessionKey)]))

        namespace = settings.get("namespace", None)
        logger.debug(''.join(['namespace=',str(namespace)]))

        conf = cli.getConfStanza('workflow_actions','pxGrid_QuarantineByIP')
        logger.debug(''.join(['conf=',str(conf)]))
        logger.debug(''.join(['ise.host=',conf['ise.host']]))

        # acquire the dispatch particulars stored in confs
        item = str(conf['ise.host'])
        logger.info(''.join(['item=',str(item)]))

        xgridHostname = item.split("|")[0]
        logger.info(''.join(['xgridHostname=',xgridHostname]))

        xgridUsername = item.split("|")[1]
        logger.info(''.join(['xgridUsername=',xgridUsername]))

        keystoreFilename = item.split("|")[2]
        logger.info(''.join(['keystoreFilename=',keystoreFilename]))

        truststoreFilename = item.split("|")[3]
        logger.info(''.join(['truststoreFilename=',truststoreFilename]))

        thisApp = 'Splunk_TA_cisco-ise'
        thisAppPath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', thisApp)
        pxgJarPath = os.path.join(thisAppPath, 'bin', 'lib', 'pxGrid_Search.jar')

        # get encrypted params (keystore and truststore passwords) from app.conf
        try:
            entities = en.getEntities(['admin', 'passwords'], namespace=thisApp,
                                          owner='nobody', sessionKey=sessionKey)
        except Exception, e:
            logger.error("Could not get %s credentials from splunk. Error: %s"
                          % (thisApp, str(e)))
            raise Exception("Could not get %s credentials from splunk. Error: %s"
                          % (thisApp, str(e)))
        keystorePassword = ''
        truststorePassword = ''
        for i, c in entities.items():
            if c['username']=='keystore':
                keystorePassword = c['clear_password']
                keystorePasswordLogged = c['password']

            elif c['username']=='truststore':
                truststorePassword = c['clear_password']
                truststorePasswordLogged = c['password']
        logger.info(''.join(['keystorePassword=',keystorePasswordLogged]))
        logger.info(''.join(['truststorePassword=',truststorePasswordLogged]))

        # get items passed in from command line
        logger.debug(''.join(['sys.argv=',str(sys.argv)]))
        for arg in sys.argv:
            #logger.debug(''.join(['arg=',arg]))
            if 'xgridAction=' in arg:
                xgridAction = arg.split('=')[1]
                logger.info(''.join(['xgridAction=',xgridAction]))
                try:
                    assert xgridAction in ['quarantine', 'unquarantine']
                except Exception, e:
                    logger.warn('xgridAction was "%s" and should be "quarantine" or "unquarantine". Error: %s'
                                      % (xgridAction, str(e)))
                    raise Exception('xgridAction was "%s" and should be "quarantine" or "unquarantine". Error: %s'
                                      % (xgridAction, str(e)))
            if 'xgridType=' in arg:
                xgridType = arg.split('=')[1]
                logger.info(''.join(['xgridType=',xgridType]))
                try:
                    assert xgridType in ['ip', 'mac']
                except Exception, e:
                    logger.warn('xgridType was "%s" and should be "ip" or "mac". Error: %s'
                                      % (xgridAction, str(e)))
                    raise Exception('xgridType was "%s" and should be "ip" or "mac". Error: %s'
                                      % (xgridAction, str(e)))
            if 'xgridTarget=' in arg:
                xgridTarget = arg.split('=')[1]
                logger.info(''.join(['xgridTarget=',xgridTarget]))
                try:
                    assert xgridTarget
                except Exception, e:
                    logger.warn('xgridTarget should contain a value. Error: %s'
                                      % (str(e)))
                    raise Exception('xgridTarget should contain a value. Error: %s'
                                      % (str(e)))

        xgridCommand = '_'.join([xgridAction,xgridType])

        text = ''
        logger.info(''.join(['LAUNCHING: java -jar ',pxgJarPath,' ',xgridHostname,' ',xgridUsername,' ',keystoreFilename,' ',keystorePasswordLogged,' ',truststoreFilename,' ',truststorePasswordLogged,' ',xgridTarget,' ',xgridCommand]))
        #os.system('java -jar /Applications/Splunk/etc/apps/Splunk_TA_cisco-ise/bin/lib/pxGrid_Search.jar ' + xgridHostname + ' ' + xgridUsername + ' ' + keystoreFilename + ' ' + keystorePassword + ' ' + truststoreFilename + ' ' + truststorePassword + ' ' + xgridTarget + ' ' + xgridCommand)
        java_cmd = ['java', '-jar', pxgJarPath, xgridHostname, xgridUsername, keystoreFilename, keystorePassword, truststoreFilename, truststorePassword, xgridTarget, xgridCommand]
        java_result = subprocess.Popen(java_cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        output, errors = java_result.communicate()
        if errors:
            send_to_Splunk = str(errors)
            logger.error(''.join(['error returned from java cmd: ',str(errors)]))
        else:
            send_to_Splunk = str(output)
            logger.info(''.join(['result from java cmd: ',str(output)]))


        if results:
            for result in results:
                pass
                #result[str(user_id)] = owner
                #result['sessionKey'] = sessionKey
                #result['namespace'] = namespace
        else:
            result={}
            #result[str(user_id)] = owner
            result['result'] = send_to_Splunk
            results.append(result)

        splunk.Intersplunk.outputResults(results)

    except Exception, e:
        import traceback
        stack =  traceback.format_exc()
        splunk.Intersplunk.generateErrorResults(str(e))
        logger.error(''.join(["\nException Detail: ",str(e),"\nTraceback: ",str(stack)]))
        raise Exception(''.join(["\nException Detail: ",str(e),"\nTraceback: ",str(stack)]))

if __name__ == '__main__':
    # setup logger
    logger = logger('pxgremediate.log')

    # dispatch to pxgrid
    pxgremediate()
