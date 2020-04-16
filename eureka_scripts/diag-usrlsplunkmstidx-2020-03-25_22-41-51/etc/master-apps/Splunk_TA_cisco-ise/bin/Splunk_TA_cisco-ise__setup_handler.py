import splunk.admin as admin
import splunk.entity as en
import logging
import re
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

'''
Copyright (C) 2005 - 2014 Splunk Inc. All Rights Reserved.
Description:  This python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values
      corresponds to handleractions = edit in restmap.conf

'''

class ConfigApp(admin.MConfigHandler):
  # set up supported arguments
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['disabled',
                  'ise.host', 'ise.version', 'link.uri',
                  'pxgrid.host','pxgrid.user','pxgrid.keystore','pxgrid.kyestore_pw',
                  'pxgrid.truststore','pxgrid.truststore_pw']:
        self.supportedArgs.addOptArg(arg)

  # load setup page
  def handleList(self, confInfo):
    confDict = self.readConf("workflow_actions")
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          # "Enable" language on page needs polarity reversed for disabled setting
          # for both ISE & pxGrid
          if key in ['disabled']:
            if int(val) == 1:
              val = '0'
            else:
              val = '1'
          # ISE support
          if key in ['link.uri','ise.version','ise.host'] and val in [None, '']:
            val = ''
          # pxGrid support
          if key in ['pxgrid.host','pxgrid.user','pxgrid.keystore','pxgrid.kyestore_pw',
                     'pxgrid.truststore','pxgrid.truststore_pw'] and val in [None, '']:
            #assert False
            val = ''

          confInfo[stanza].append(key, val)

  # save setup page to workflow_actions.conf
  def handleEdit(self, confInfo):
    name = self.callerArgs.id
    args = self.callerArgs
    # build_link will become False if invalid condition occurs (workflow action will also be disabled if False, prior to saving)
    build_link = True
    logger.debug(''.join(['name=',str(name),' args=',str(args)]))

    # "Enable" language on page needs polarity reversed for disabled setting
    if int(self.callerArgs.data['disabled'][0]) == 1:
      self.callerArgs.data['disabled'][0] = '0'
    else:
      self.callerArgs.data['disabled'][0] = '1'

    if name in ['pxGrid_QuarantineByIP','pxGrid_UnQuarantineByIP','pxGrid_QuarantineByMAC','pxGrid_UnQuarantineByMAC']:
        # This is exclusively for pxGrid setup, not ISE setup
        pass
        """
        MOVED CREDENTIAL HANDLING TO SETUP.XML

        # grab session key for credential work via REST
        sessionKey = self.getSessionKey()

        # Create Encrypted Credential in app.conf via REST API
        # TODO: Check if cred exists before attempting to create, if so update instead
        entities = en.getEntities('storage/passwords', search="realm=\"" + "description" + "\"", sessionKey=sessionKey)
        logger.debug(''.join(['entities=',str(entities)]))
        creds = en.getEntity('/storage/passwords/','_new', sessionKey=sessionKey)
        creds["name"] = "user_name"
        creds["password"] = "password"
        creds["realm"] = "description"
        creds.namespace = "Splunk_TA_cisco-ise"
        en.setEntity(creds, sessionKey=sessionKey)
        """

    else:
        # This is exclusively for non-pxGrid setup, ISE setup
        # if ise version is not 1.2 or 1.3, disable workflowa action and notify user
        try:
          self.callerArgs.data['ise.version'][0]
        except:
          logger.warning('Well, ise version was not found')
        else:
          if self.callerArgs.data['ise.version'][0] == '1.2':
            ise_version = '1.2'
          else:
            if self.callerArgs.data['ise.version'][0] == '1.3':
              ise_version = '1.3'
            else:
              if self.callerArgs.data['ise.version'][0] == '1.4':
                ise_version = '1.4'
              else:
                if self.callerArgs.data['ise.version'][0] == '2.0':
                  ise_version = '2.0'
                else:
                  logger.warning(''.join(['Disabling ',name,' due to incorrect version "',self.callerArgs.data['ise.version'][0],'" entered. The value should be 1.2, 1.3, 1.4 or 2.0']))
                  self.callerArgs.data['ise.version'][0] = 'Disabled: Please enter ISE version "1.2","1.3","1.4" or "2.0" and enable'
                  build_link = False

        # if host is empty or contains a space, present warnings & disable workflow action
        if (self.callerArgs.data['ise.host'][0] in [None, '']) or (bool(re.search("([^A-Za-z\d\.\-\_]+)|(\s)",self.callerArgs.data['ise.host'][0]))):
          logger.warning(''.join(['Disabling ',name,' due to invalid host "',self.callerArgs.data['ise.host'][0],'" entered. The value should be a valid hostname']))
          self.callerArgs.data['ise.host'][0] = 'Disabled: Please enter a valid ISE host and enable'
          build_link = False
        else:
          ise_host = self.callerArgs.data['ise.host'][0]

        # if all went well, build workflow action target based on version, otherwise disable workflow action
        if build_link == True:
          # build base link based on version
          if ise_version == '1.3' or ise_version == '1.4' or ise_version == '2.0'  :
            self.callerArgs.data['link.uri'][0] = '/'.join(['https:/',ise_host,'admin/API'])
          if ise_version == '1.2':
            self.callerArgs.data['link.uri'][0] = '/'.join(['https:/',ise_host,'ise'])
          # build out link based on workflow action
          if name == "EPS_Quarantine_By_Framed_IP_Address":
            self.callerArgs.data['link.uri'][0] = '/'.join([self.callerArgs.data['link.uri'][0],'eps/QuarantineByIP/$Framed_IP_Address$'])
          elif name == "EPS_QuarantineByIPAddress":
            self.callerArgs.data['link.uri'][0] = '/'.join([self.callerArgs.data['link.uri'][0],'eps/QuarantineByIP/$IpAddress$'])
          elif name == "EPS_QuarantineByMAC":
            self.callerArgs.data['link.uri'][0] = '/'.join([self.callerArgs.data['link.uri'][0],'eps/QuarantineByMac/$MacAddress$'])
          elif name == "EPS_UnquarantineByIPAddress":
            self.callerArgs.data['link.uri'][0] = '/'.join([self.callerArgs.data['link.uri'][0],'eps/UnQuarantineByIP/$IpAddress$'])
          elif name == "EPS_UnquarantineByMAC":
            self.callerArgs.data['link.uri'][0] = '/'.join([self.callerArgs.data['link.uri'][0],'eps/UnQuarantineByMac/$MacAddress$'])
        else:
          self.callerArgs.data['disabled'][0] = '1'

    # commit to conf
    logger.debug(''.join(["Attempting to write stanza ", str(name)]))
    try:
        self.writeConf('workflow_actions', name, self.callerArgs.data)
    except:
        logger.error(''.join(["Failed to write stanza ", str(name)]))
    else:
        logger.debug(''.join(["Wrote to stanza ", str(name)]))


# define logger
def setup_logger(name, level=logging.WARNING, maxBytes=25000000, backupCount=5):
    '''
    Set up a default logger.

    @param name: The log file name.
    @param level: The logging level.
    @param maxBytes: The maximum log file size before rollover.
    @param backupCount: The number of log files to retain.
    '''

    # Strip ".py" from the log file name if auto-generated by a script.
    if '.py' in name:
        name = name.replace(".py", "")

    logfile = make_splunkhome_path(["var", "log", "splunk", name + '.log'])

    logger = logging.getLogger(name)
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.level = level

    # Prevent re-adding handlers to the logger object, which can cause duplicate log lines
    handler_exists = any([True for h in logger.handlers if h.baseFilename == logfile])
    if not handler_exists:
        file_handler = logging.handlers.RotatingFileHandler(logfile, mode='a', maxBytes=maxBytes, backupCount=backupCount)
        formatter = logging.Formatter('%(asctime)s %(levelname)s pid=%(process)d tid=%(threadName)s file=%(filename)s:%(funcName)s:%(lineno)d | %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

# setup logging
logger = setup_logger('Splunk_TA_cisco-ise', level=logging.DEBUG)

# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
