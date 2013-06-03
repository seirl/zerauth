#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import yaml
import requests
import argparse
import lxml.html
import io
import time
import signal

CFG = {}


def portal_query(section, action, authkey=''):
    url = '{}://{}:{}/cgi-bin/zscp'.format(
        CFG['server']['protocol'], CFG['server']['host'],
        CFG['server']['port'])

    print('Sending query with action={}, section={}, authkey={} to {}'.format(
        action, section, repr(authkey), url))

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

    return requests.post(url, data=data)


def get_authkey(response):
    tree = lxml.html.parse(io.BytesIO(response.content))
    candidates = tree.xpath("//input[@type='hidden'][@name='Authenticator']")
    authkey = candidates[0].value

    if authkey:
        print('Authentification key found:', repr(authkey))
    return authkey


class Zerauth:
    authkey = ''
    enabled = True

    def connect(self):
        self.authkey = get_authkey(portal_query('CPAuth', 'Authenticate'))
        portal_query('CPGW', 'Connect', self.authkey)
        portal_query('ClientCTRL', 'Connect', self.authkey)
        self.enabled = True

    def run(self):
        time.sleep(CFG['server']['renew_delay'])
        while self.enabled:
            portal_query('CPGW', 'Renew', self.authkey)
            time.sleep(CFG['server']['renew_delay'])

    def logout(self):
        self.enabled = False
        portal_query('CPGW', 'Disconnect', self.authkey)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Zeroshell Captive portal auth daemon')
    parser.add_argument('--config', dest='config', default='zerauth.yml',
        help='configuration file, informations about the captive portal')
    args = parser.parse_args()
    CFG = yaml.load(open(args.config))

    z = Zerauth()
    z.connect()

    def sigint_handler(signal, frame):
        z.logout()
    signal.signal(signal.SIGINT, sigint_handler)

    z.run()
