import os
from logging import _levelNames
PARENT = os.path.sep+os.path.pardir
PATH=os.path.abspath(__file__+PARENT)
while os.path.basename(PATH)!='bin':
    PATH=os.path.abspath(PATH+PARENT)
DEFAULT=os.path.abspath(PATH+PARENT)+os.path.sep+'default'+os.path.sep+'log_level'
LOCAL=os.path.abspath(PATH+PARENT)+os.path.sep+'local'+os.path.sep+'log_level'
def level_from_file():
    try:
        with open(LOCAL) as f:
            level=f.readline().strip()
        if level in _levelNames:
            return level
    except:
        pass

    try:
        with open(DEFAULT) as f:
            level=f.readline().strip()
        if level in _levelNames:
            return level
    except:
        pass

    return 'INFO'


try:
    import splunk.clilib.cli_common as scc
    from splunk.rest import simpleRequest

    def get_level(name, token):
        HOST = scc.getMgmtUri()
        (response,level)=simpleRequest(HOST + '/services/properties/log_info/%s/level' % name, sessionKey=token)
        if level in _levelNames:
            return level
        else:
            return 'INFO'

    def set_level(name, token, level):
        if level in _levelNames:
            HOST = scc.getMgmtUri()
            response=simpleRequest(HOST + '/services/properties/log_info/%s' % name, postargs={'level':level},sessionKey=token)
            return response
        else:
            return None

except:
    def get_level(name, token):
        return level_from_file()


    def set_level(name, level, token):
        return None