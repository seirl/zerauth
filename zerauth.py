#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import argparse
import functools
import io
import logging
import lxml.html
import requests
import subprocess
import signal
import sys
import time
import yaml
from requests.exceptions import RequestException

CFG = {}

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
CSTOP = '\033[0m'

def portal_query(section, action, authkey='', timeout=30):
    url = '{}://{}:{}/cgi-bin/zscp'.format(
        CFG['server']['protocol'], CFG['server']['host'],
        CFG['server']['port'])

    logging.info('[{cyan}{section:^10}{cs}][{green}{action:^12}{cs}]'
                 ' Query {url} with key {yellow}{key}{cs}'.format(
        action=action, section=section, url=url,
        key=repr(authkey[:10] + '…' if authkey else None),
        cyan=CYAN, green=GREEN, yellow=YELLOW, cs=CSTOP
    ))

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


try:
    import systemd.daemon
    systemd_notify = functools.partial(systemd.daemon.notify, "READY=1")
except ImportError:
    def systemd_notify():
        try:
            subprocess.call(["systemd-notify", "--ready"])
        except FileNotFoundError:
            pass


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
            systemd_notify()
        except (LookupError, RequestException) as e:
            if 'http.client.BadStatusLine' in str(e):
                logging.error('The port does not match with the protocol. '
                              'Please check your configuration.')
                sys.exit(1)
            logging.error('Connection failed: "{}", retrying in 30s'.format(e))
            time.sleep(30)
            self.connect()

    def run(self):
        while True:
            try:
                time.sleep(CFG['server']['renew_delay'])
                while self.enabled:
                    portal_query('CPGW', 'Renew', self.authkey)
                    last = time.time()
                    time.sleep(CFG['server']['renew_delay'])
                    # In case of suspend
                    if time.time() - last > CFG['server']['renew_delay'] * 1.5:
                        raise RuntimeError("System has been suspended")
            except (RequestException, RuntimeError) as e:
                logging.error(
                        'Renew failed: "{}", trying to reconnect.'.format(e))
                self.connect()

    def logout(self):
        self.enabled = False
        portal_query('CPGW', 'Disconnect', self.authkey)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Zeroshell Captive portal auth daemon')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
            help='hide verbose logs')
    parser.add_argument('-c', '--config', dest='config', default='zerauth.yml',
            help='captive portal configuration')
    args = parser.parse_args()

    logging.basicConfig(level=logging.ERROR if args.quiet else logging.INFO,
            format='%(levelname)s:%(asctime)s: %(message)s')

    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    CFG = yaml.load(open(args.config))

    z = Zerauth()
    z.connect()

    def stop_handler(signal=None, frame=None):
        if signal:
            logging.info('Signal received: {}. Logging out.'.format(signal))
        z.logout()
        sys.exit(0)

    def reload_handler(signal, frame):
        if signal:
            logging.info('Signal received: {}. Reloading.'.format(signal))
        CFG.update(yaml.load(open(args.config)))

    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, stop_handler)

    if hasattr(signal, 'SIGUSR1'):
        signal.signal(signal.SIGUSR1, reload_handler)

    try:
        z.run()
    except KeyboardInterrupt:
        stop_handler('SIGINT')
