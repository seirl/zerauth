# Synopsis

**zerauth** is a ZeroShell auto-login daemon. It can handle unstable
connections and reconnects itself when the renewal requests timeout.

# Requirements

* python3
* pip-3

# Install

    $ git clone git@bitbucket.org:serialk/zerauth.git
    $ cd zerauth
    # pip install -r requirements.txt

    # cp zerauth.py /usr/bin/zerauth
    # cp zerauth.yml /etc/zerauth.conf

# Config

    $ vim /etc/zerauth.conf

    login:
        username:               # Your username
        password:               # Your password
        domain:                 # The domain 

    server:
        host: 192.168.0.1       # The hostname / IP of the captive portal
        port: 12080             # The port associated with the right protocol
        protocol: http          # http or https (must match with 'port')
        renew_delay: 40         # Seconds between each renew request

# systemd

    $ cp systemd/zerauth.service /etc/systemd/system
    $ systemctl enable zerauth
    $ systemctl start zerauth
