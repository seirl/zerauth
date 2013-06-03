#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import yaml
import requests
import argparse
import lxml.html
import io
import time

CFG = {}


def portal_query(section, action, authkey=''):
    url = '{}://{}:{}/cgi-bin/zscp'.format(
        CFG['server']['protocol'], CFG['server']['host'],
        CFG['server']['port'])

    print('Sending query with action={}, section={}, authkey={} to {}'.format(
        action, section, authkey, url))

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
    print(lxml.html.tostring(tree).decode('utf-8'))
    candidates = tree.xpath("//input[@type='hidden'][@name='Authenticator']")
    authkey = candidates[0].value

    if authkey:
        print('Authentification key found:', repr(authkey))
    return authkey


def run():
    authkey = get_authkey(portal_query('CPAuth', 'Authenticate'))
    authkey = get_authkey(portal_query('CPGW', 'Connect', authkey))
    authkey = get_authkey(portal_query('ClientCTRL', 'Connect', authkey))

    while True:
        time.sleep(CFG['server']['renew_delay'])
        authkey = get_authkey(portal_query('CPGW', 'Renew', authkey))


def logout(authkey):
    portal_query('CPGW', 'Disconnect', authkey)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Zeroshell Captive portal auth daemon')
    parser.add_argument('--config', dest='config', default='zerauth.yml',
        help='configuration file, informations about the captive portal')
    args = parser.parse_args()
    CFG = yaml.load(open(args.config))

    run()
