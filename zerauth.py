#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import yaml
import requests
from requests.exceptions import RequestException
import argparse
import lxml.html
import io
import time
import signal
import sys
import logging

CFG = {}


def portal_query(section, action, authkey='', timeout=30):
    url = '{}://{}:{}/cgi-bin/zscp'.format(
        CFG['server']['protocol'], CFG['server']['host'],
        CFG['server']['port'])

    logging.info('Query: action={}, section={}, authkey={} to {}'.format(
        action, section, repr(authkey[:10] + '…' if authkey else None), url))

    data = {
        'U': CFG['login']['username'],
        'P': CFG['login']['password'],
        'Realm': CFG['login']['domain'],
        'Action': action,
        'Section': section,
        'ZSCPRedirect': '_:::_',
    }

    if authkey:
        data['Authenticator'] = authkey

    return requests.post(url, data=data, timeout=timeout, verify=False)


def get_authkey(response):
    tree = lxml.html.parse(io.BytesIO(response.content))
    candidates = tree.xpath("//input[@type='hidden'][@name='Authenticator']")
    authkey = candidates[0].value
    return authkey


class Zerauth:
    authkey = ''
    enabled = True

    def connect(self):
        try:
            r = portal_query('CPAuth', 'Authenticate')
            if 'Access Denied' in r.text:
                logging.error('Login failed, please check your login/password')
                sys.exit(1)
            self.authkey = get_authkey(r)
            if not self.authkey:
                raise LookupError('AuthKey not found.')
            portal_query('CPGW', 'Connect', self.authkey)
            portal_query('ClientCTRL', 'Connect', self.authkey)
            self.enabled = True
        except (LookupError, RequestException) as e:
            logging.error('Connection failed: "{}", retrying in 30s'.format(e))
            time.sleep(30)
            self.connect()

    def run(self):
        try:
            time.sleep(CFG['server']['renew_delay'])
            while self.enabled:
                portal_query('CPGW', 'Renew', self.authkey)
                time.sleep(CFG['server']['renew_delay'])
        except RequestException as e:
            logging.error('Renew failed: "{}", trying to reconnect.'.format(e))
            self.connect()
            self.run()

    def logout(self):
        self.enabled = False
        portal_query('CPGW', 'Disconnect', self.authkey)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Zeroshell Captive portal auth daemon')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
            help='display verbose logs')
    parser.add_argument('-c', '--config', dest='config', default='zerauth.yml',
            help='captive portal configuration')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR,
            format='%(levelname)s:%(asctime)s: %(message)s')
    CFG = yaml.load(open(args.config))

    z = Zerauth()
    z.connect()

    def stop_handler(signal, frame):
        z.logout()
        sys.exit(0)

    def reload_handler(signal, frame):
        CFG.update(yaml.load(open(args.config)))

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGQUIT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    if hasattr(signal, 'SIGUSR1'):
        signal.signal(signal.SIGUSR1, reload_handler)

    try:
        z.run()
    except KeyboardInterrupt:
        stop_handler()
