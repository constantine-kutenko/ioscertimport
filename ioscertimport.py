import os
import sys
import random
import string
import netmiko
import logging
import argparse
import subprocess
from logging import handlers

VERSION = "0.0.1"

TRUSTPOINT_NAME = "CA_LETSENCRYPT"
LOG_FILE = "/var/log/ioscertimport.log"


def get_args() -> object:
    """ Parses command line arguments """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-H',
        '--host',
        default='127.0.0.1',
        type=str,
        help="IPv4 address of a remote router. Default: %(default)s"
    )
    parser.add_argument(
        '-p',
        '--port',
        default=22,
        type=int,
        help="TCP port of a remote router to connect to. Default: %(default)d"
    )
    parser.add_argument(
        "-u", 
        '--username',
        type=str,
        help="Username that will be used upon connection"
    )
    parser.add_argument(
        '-P',
        '--password',
        type=str,
        help="Password that will be used upon connection"
    )
    parser.add_argument(
        '-k',
        '--sshkey',
        type=str,
        help="Path to the router's public SSH key"
    )
    parser.add_argument(
        '-K',
        '--tlskey',
        default='privkey.pem',
        type=str,
        help="Path to the TLS private key file"
    )
    parser.add_argument(
        '-c',
        '--tlscert',
        default='cert.pem',
        type=str,
        help="Path to the TLS server certificate file"
    )
    parser.add_argument(
        '-C',
        '--tlsca',
        default='chain.pem',
        help="Path to the TLS CA certificate file"
    )
    parser.add_argument(
        '-S',
        '--keypassword',
        help="Password for encrypting the private key"
    )
    parser.add_argument(
        '-l',
        '--log-level',
        default='info',
        choices=('info', 'debug','warning'),
        help="Verbosity level"
    )
    parser.add_argument(
        '-g',
        '--gateway',
        help="Gateway name to update"
    )
    parser.add_argument(
        '-s',
        '--secure',
        help="Encrypt private key with randomly generated passphrase (--keypassword and --password are ignored)",
        action="store_true"
    )
    return parser.parse_args()


def verify_binary(binary: str) -> bool:
    """ Checks whether OpenSSL package presents within the system """
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
    fpath, _ = os.path.split(binary)
    if fpath:
        if is_exe(binary):
            return True
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            global executable
            executable = os.path.join(path, binary)
            if is_exe(executable):
                log.debug("%s was found in %s" % (binary, executable))
                return True
    return False


def verify_tls_files(key: str, cert: str, ca: str) -> bool:
    """ Checks that necessary TLS files represent and not empty """
    if os.path.isfile(key) and os.stat(key).st_size != 0:
        if os.path.isfile(cert) and os.stat(cert).st_size != 0:
            if os.path.isfile(ca) and os.stat(ca).st_size != 0:
                return True
    return False


def validate_cert(key: str, cert: str) -> bool:
    """ Validates the certificate provided and matches it against the key """
    # Verify that the certificate matches the key
    process = subprocess.Popen('openssl x509 -noout -modulus -in {} | openssl md5'.format(cert),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    cert_checksum, _ = process.communicate()
    process = subprocess.Popen('openssl rsa -noout -modulus -in {} | openssl md5'.format(key),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    key_checksum, _ = process.communicate()
    if cert_checksum == key_checksum:
        return True
    else:
        log.critical("The certificate does not match the key provided\n\tCertificate checksum: %s\n\tKey checksum: %s" % 
            (cert_checksum[9:].decode('UTF-8').strip(), key_checksum[9:].decode('UTF-8').strip()))
        return False


def set_key_password(secure: bool, key_password: str, router_password: str) -> str:
    """ Defines a password to be used to encrypt the key """
    if secure:
        # Generate random passphrase for encrypting the private key
        log.debug("A random passphrase for encypting the key has been generated")
        return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(22))
    else:
        # If key password is not provided explicitly, use router's password to encrypt the private key
        if key_password == '':
            log.debug("RSA key password has not been provided. The router's password will be used instead")
            return key_password
        else:
            return router_password


def encrypt_key(key: str, password: str) -> bool:
    """ Encrypts TLS key with a password defined """
    if not subprocess.call('openssl rsa -in {} -out {}.enc -des3 -passout pass:"{}" > /dev/null'.format(key, key, password),
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
        ):
        if os.path.isfile(key + '.enc'):
            return True
    return False


def remove_crypto_config(conn: object, trustpoint: str):
    """ Removes the current trustpoint and associated key and certificates """
    # Remove the key
    if conn.send_command('show crypto key mypubkey rsa ' + trustpoint) != '':
        try:
            conn.send_config_set(['crypto key zeroize rsa ' + trustpoint, 'yes'], cmd_verify=False)
            log.debug("Key %s has been removed" % (trustpoint))
        except Exception as ex:
            log.error("Could not remove key %s due to %s" % (trustpoint, ex))
    else:
        log.debug("Key %s has not been found" % (trustpoint))
    # Remove the certificate
    if conn.send_command('show crypto pki certificates ' + trustpoint) != '':
        try:
            conn.send_config_set(['no crypto pki certificate chain ' + trustpoint, 'yes'], cmd_verify=False)
            log.debug("Certificate %s has been removed" % (trustpoint))
        except Exception as ex:
            log.error("Could not remove certificate %s due to %s" % (trustpoint, ex))
    else:
        log.debug("Certificate %s has not been found" % (trustpoint))
    # Remove trustpoit
    if conn.send_command('show crypto pki trustpoint ' + trustpoint) != '':
        try:
            conn.send_config_set(['no crypto pki trustpoint ' + trustpoint, 'yes'], cmd_verify=False)
            log.debug("Trustpoint %s has been removed" % (trustpoint))
        except Exception as ex:
            log.error("Could not remove trustpoint %s due to %s" % (trustpoint, ex))
    else:
        log.debug("Trustpoint %s has not been found" % (trustpoint))


def create_trustpoint(conn: object, trustpoint: str) -> bool:
    """ Creates a new trustpoint """
    try:
        conn.send_config_set(['crypto pki trustpoint ' + trustpoint])
        conn.send_config_set(['enrollment terminal pem'])
        return True
    except Exception as ex:
        log.error("Could not create trustpoint %s due to %s" % (trustpoint, ex))
        return False


def import_certs(conn: object, trustpoint: str, tlsca: str, tlskey: str, tlscert: str, password: str) -> bool:
    """ Imports the private key and certificates into the respective trustpoint """
    if conn.send_command('show crypto key mypubkey rsa ' + trustpoint) == '':
        if conn.send_command('show crypto pki certificates '+ trustpoint) == '':
            cmd = ['crypto pki import {} pem terminal password {}'.format(trustpoint, password)]
            certificate_order = [tlsca, tlskey + '.enc', tlscert]
            # Import each TLS entity in order
            for tlsfile in certificate_order:
                with open(tlsfile, 'r') as handler:
                    cmd.append(handler.read())
                    cmd.append('quit')
            try:
                conn.send_config_set(cmd, cmd_verify=False)
            except Exception as ex:
                log.error("Could not import certificates due to: %s" % (ex))
                return False
    # Verify newly imported certificate and key
    if conn.send_command('show crypto key mypubkey rsa ' + trustpoint) != '':
        if conn.send_command('show crypto pki certificates '+ trustpoint) != '':
            return True
    return False


def setup_gateway(conn: object, trustpoint: str, gateway: str) -> bool:
    """ Tries to find the current gateway in configuration and update it """
    if gateway is None:
        # If gateway name is not provided in arguments, make an attempt to get it from configuration
        output = conn.send_command('show webvpn gateway')
        gateway_name = output.split('\n')[0].split(': ')[1]
    else:
        gateway_name = gateway

    if gateway_name == '':
        log.error("Could not find any gateway configured or it was not provided explicitly")
        return False
    else:
        log.debug("Defined a gateway as %s" % gateway_name)
        try:
            conn.send_config_set(
                [
                    'webvpn gateway ' + gateway_name,
                    'no inservice',
                    'no ssl trustpoint ' + trustpoint,
                    'ssl trustpoint ' + trustpoint,
                    'inservice'
                ],
                cmd_verify=False
            )
            return True
        except Exception as ex:
            log.error("Could not update configuration for gateway %s due to %s" % (gateway_name, ex))
            return False


def main():
    params = get_args()

    # Logging will be done to stdout and a log file simultaneously
    global log
    file_handler = logging.handlers.WatchedFileHandler(LOG_FILE)
    stdout_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [ %(levelname)s ] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    stdout_handler.setFormatter(formatter)
    log = logging.getLogger('app')
    log.setLevel(getattr(logging, params.log_level.upper()))
    log.addHandler(file_handler)
    log.addHandler(stdout_handler)

    if not verify_binary('openssl'):
        log.critical("OpenSSL was not found in the system. Please install before running the script. Abort!")
        sys.exit(1)

    # Verify certificate and key files
    if not verify_tls_files(params.tlskey, params.tlscert, params.tlsca):
        log.critical("Unable to locale TLS file(s) or the files are empty:\n\t%s\n\t%s\n\t%s. Abort!" % (
            params.tlskey,
            params.tlscert,
            params.tlsca
        ))
        sys.exit(1)

    # Validate certificate
    if validate_cert(params.tlskey, params.tlscert):
        log.debug("TLS certificate matches the respective private key")
    else:
        log.error("TLS certificate does not match the respective private key. Abort!")
        sys.exit(1)

    # Define TLS key password
    key_password = set_key_password(params.secure, params.keypassword, params.password)

    # Encrypt the TLS private key with the password
    if encrypt_key(params.tlskey, key_password):
        log.debug("Private key has successfully been encrypted")
    else:
        log.error("Unable encrypt the private key. Abort!")
        sys.exit(1)

    # Connect to the router
    try:
        if params.sshkey is not None:
            # The SSH key file must exist to be utilized
            if (os.path.isfile(params.sshkey) and os.stat(params.sshkey).st_size != 0):
                ssh = netmiko.ConnectHandler(
                    device_type='cisco_ios',
                    host=params.host,
                    port=params.port,
                    username=params.username,
                    use_keys=True,
                    key_file=params.sshkey,
                    global_delay_factor=2
                )
            else:
                log.error("SSH key file does not exist: %s. Abort!" % params.sskey)
                sys.exit(1)
        else:
            ssh = netmiko.ConnectHandler(
                device_type='cisco_ios',
                host=params.host,
                port=params.port,
                username=params.username,
                password=params.password,
                global_delay_factor=2
            )
        log.info("Connected to %s:%d as %s" % (params.host, params.port, params.username))
        ssh.find_prompt()
    except netmiko.ssh_exception.NetMikoAuthenticationException:
        log.error("Unable to authenticate against %s:%d as %s. Abort!" % (params.host, params.port, params.username))
        sys.exit(1)
    except Exception as ex:
        log.error("Could not connect to %s:%d due to %s. Abort!" % (params.host, params.port, ex))
        sys.exit(1)

    # Remove the key, certificates and trustpoint
    remove_crypto_config(ssh, TRUSTPOINT_NAME)
    # Create a new trustpoint
    if create_trustpoint(ssh, TRUSTPOINT_NAME):
        log.debug("New trustpoint %s has been created" % TRUSTPOINT_NAME)
        # Upload the key and certificates
        if import_certs(ssh, TRUSTPOINT_NAME, params.tlsca, params.tlskey, params.tlscert, key_password):
            log.info("Certificates have been imported for trustpoint %s" % TRUSTPOINT_NAME)
            # Setup the gateway
            if setup_gateway(ssh, TRUSTPOINT_NAME, params.gateway):
                log.debug("Gateway has been updated")
                # Get information about the certificate just installed
                output = ssh.send_command('show crypto pki certificates ' + TRUSTPOINT_NAME)
                if output is not None:
                    cert_sn = output.split('\n')[2].split(': ')[1]
                    cert_expire_date = output.split('\n')[13].split(': ')[1]
                    log.info("Certificate serial number: %s" % cert_sn)
                    log.info("Certificate expires on: %s" % cert_expire_date)
    ssh.disconnect()
    log.info("Connection to %s:%d closed" % (params.host, params.port))


if __name__ == "__main__":
    main()
