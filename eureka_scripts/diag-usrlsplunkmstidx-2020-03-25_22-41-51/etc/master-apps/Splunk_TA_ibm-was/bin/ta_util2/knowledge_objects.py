import logging
import ta_util2.xml_dom_parser as xdp
import ta_util2.rest as rest
import ta_util2.log_files as log_files


_LOGGER = logging.getLogger(log_files.ta_util_conf)


class KnowledgeObjectManager(object):

    def __init__(self, splunkd_uri, session_key):
        self.splunkd_uri = splunkd_uri
        self.session_key = session_key

    def apps(self):
        """
        @return: a list of dict containing apps if successfuly otherwise None
        """

        uri = "{}/services/apps/local?count=0&offset=0".format(
            self.splunkd_uri)
        apps = self._do_request(uri, "GET", None, "Failed to get apps")
        if apps:
            for app in apps:
                app["name"] = app["stanza"]
        return apps

    def indexes(self):
        """
        @return: a list of dict containing indexes if successfuly
                 otherwise None
        """

        uri = "{}/services/data/indexes/?count=0&offset=0".format(
            self.splunkd_uri)
        indexes = self._do_request(uri, "GET", None, "Failed to get indexes")
        if indexes:
            for index in indexes:
                index["name"] = index["stanza"]
        return indexes

    def _do_request(self, uri, method, payload, err_msg):
        resp, content = rest.splunkd_request(uri, self.session_key, method,
                                             data=payload, retry=3)
        if resp is None and content is None:
            return None

        if resp.status in (200, 201):
            return xdp.parse_conf_xml_dom(content)
        else:
            _LOGGER.error("%s, reason=%s", err_msg, resp.reason)
        return None
