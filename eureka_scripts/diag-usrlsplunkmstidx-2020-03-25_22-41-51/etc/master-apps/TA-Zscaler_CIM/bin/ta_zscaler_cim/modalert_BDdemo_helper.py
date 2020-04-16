
# encoding = utf-8

def query_url(helper, url, apikey, themethod):
    import json
    import re, urllib
    from httplib2 import Http
    
    if not url or not apikey:
        helper.log_error('Some parameters are missing. The required are: apikey and url.')
        return

    uri = 'https://ec2-35-164-0-118.us-west-2.compute.amazonaws.com'
    http = helper.build_http_connection(helper.proxy, timeout=30)
    data = {
        'resource': '{}'.format(url) ,
        'apikey': '{}'.format(apikey) ,
    }
    
    #No headers needed in this case
    headers = {
    #'header1' : 'header_value'
    }

    resp_headers, content = http.request(uri, method=themethod,
                                     body=urllib.urlencode(data), headers=headers)
                                     
    if resp_headers.status not in (200, 201, 204):
        helper.log_error('Failed to post: url={}, HTTP Error={}, content={}'.format( url, resp_headers.status, content))
    else:

        helper.log_info('Successfully Posted data to url {}, content={}'.format(url, content))
        return content


def process_event(helper, *args, **kwargs):

    helper.log_info("Alert action BDdemo started.")

    #query the url from setup
    url = helper.get_param("url")
    helper.log_info("url={}".format(url))
    apikey = helper.get_global_setting("apikey") 
    
    #call the query URL REST Endpoint and pass the url and API token
    content = query_url(helper, url, apikey, 'POST')  

    #write the response returned by Virus Total API to splunk index
    helper.addevent(content, sourcetype="VirusTotal")
    helper.writeevents(index="main", host="localhost", source="BDdemo")
    
    return 0
