# ioscertimport

## Table of Contents

* [Overview](#overview)
* [Requirements](#requirements)
* [Usage](#usage)
* [Security](#security)

## Overview

`ioscertimport` is a Python3 application that is intended to work along with [Let's Encrypt](https://letsencrypt.org) [Certbot](https://certbot.eff.org/) and is meant to import TLS certificates and the private key into a Cisco IOS-based device upon certificate's update. The respective WebVPN gateway is configured and restarted in order to embrace the new certificate and key.

## Requirements

* [OpenSSL toolkit](https://www.openssl.org)
* [Python 3.x](https://www.python.org)
* [`robotframework-sshlibrary`](https://pypi.org/project/robotframework-sshlibrary/) library

To install `robotframework-sshlibrary` one can either issue:

```bash
pip3 install robotframework-sshlibrary
```

or

```bash
pip3 install -r requirements.txt
```

## Usage

The application is designed to be run as a standalone Python script and accepts command line parameters pointed below.

```bash
python3 ioscertimport.py \
    --host <ios_device_ipv4_addr> \
    --port 22 \
    --username <ios_device_username> \
    --password <ios_device_password> \
    --tlskey /path/to/privkey.pem \
    --tlscert /path/to/cert.pem \
    --tlsca /path/to/chain.pem \
    --gateway <gateway-name> \
    --log-level debug \
    --secure
```

It is recommended to set up a `post_hook` for a specific domain for which a certificate is uploaded. When `Certbot` updates the certificate, a command pointed in the `post_hook` is triggered and executed. Assuming that a certificate for domain `example.com` is issued, then the configuration file `/etc/letsencrypt/renewal/example.com.conf` can have the following `post_hook` configured:

```bash
post_hook = "/usr/bin/python3 ioscertimport.py --host <device_ipv4_addr> --port 22 --username <username> --password <password> --tlskey /etc/letsencrypt/live/example.com/privkey.pem --tlscert /etc/letsencrypt/live/example.com/cert.pem --tlsca /etc/letsencrypt/live/example.com/chain.pem --gateway <gateway-name> --log-level debug"
```

After the initial configuration is done, it is possible to test the overall solution by triggering renewing a certificate forcibly with the following command:

```bash
certbot renew --force-renew --cert-name example.com
```

The results of executing the application will be written in the log file `/var/log/ioscertimport.log`.

## Security

Despite the fact that being imported into the device the private key becomes non-exportable, there is still possibility for security improvements. By providing `--secure` flag it is possible to force generating random passphrase that will subsequently be used to encrypt the key.
