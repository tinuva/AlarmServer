"""Smartthings module"""
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from tornado.httpclient import AsyncHTTPClient
from tornado import gen

from core import logger
from core.events import Events

class Smartthings(object):
    """Smartthings plugin class"""
    def __init__(self, config):
        """Init function for smartthings plugin"""
        self.config = config
        config.SMARTTHINGS_ENABLE = config.get_val('smartthings', 'enable', False, 'bool')
        if config.SMARTTHINGS_ENABLE:
            config.SMARTTHINGS_ACCESS_TOKEN = config.get_val('smartthings', 'access_token', False, 'str')
            config.SMARTTHINGS_URL_BASE = config.get_val('smartthings', 'url_base', False, 'str')
            config.SMARTTHINGS_APP_ID = config.get_val('smartthings', 'app_id', False, 'str')
            config.SMARTTHINGS_EVENT_CODES = config.get_val('smartthings', 'event_codes', [], 'listint')
            logger.debug('SMARTTHINGS Enabled - event codes: %s' % (",".join([str (i) for i in config.SMARTTHINGS_EVENT_CODES])))
            events.register('statechange', sendStNotification, [], [])
            events.register('stateinit', sendStNotification, [], [])

    @gen.coroutine
    def send_notification(self, event_type, type, parameters, code, event, message, default_status):
        """Send smartthings notificiation"""
        http_client = AsyncHTTPClient()
        url = 'garbage'
        if type == 'zone':
            url = config.SMARTTHINGS_URL_BASE + "/" + config.SMARTTHINGS_APP_ID + "/panel/" + str(code) + "/" + str(int(parameters)) + "?access_token=" + config.SMARTTHINGS_ACCESS_TOKEN
        elif type == 'partition':
            url = config.SMARTTHINGS_URL_BASE + "/" + config.SMARTTHINGS_APP_ID + "/panel/" + str(code) + "/" + str(int(parameters[0])) + "?access_token=" + config.SMARTTHINGS_ACCESS_TOKEN
        else:
            logger.debug('Smartthings unhandled type: ' + type)
            return
        # logger.debug('Smartthings will send %s request: %s' % (type, url))
        try:
            res = yield http_client.fetch(url, method='GET')
            logger.debug('Smartthings notification sent')
        except:
            logger.debug('Smartthings exception for url %s' % url)
        # logger.debug('Smartthings result: %s' % res)
