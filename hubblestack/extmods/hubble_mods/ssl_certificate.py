# -*- encoding: utf-8 -*-
"""
Module to fetch ssl certificate data. Can be used by both Audit/FDG

Audit Example:
---------------
ssl_cert_check:
  description: 'ssl cert check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: ssl_certificate
      items:
        - args:
            host_ip: 'www.google.com'
            host_port: 443
            ssl_timeout: 10
            path: /path/to/pem/file
          comparator:
            type: certificate
            compare:
                not_before: 30 # maximum number of days until the certificate becomes valid (Optional)
                               # the check is failed if the certificate becomes valid in more than 30 days
                not_after: 45  # minimum number of days until certificate expires (Optional)
                               # the check is failed if the certificate expires in less than 45 days
                fail_if_not_before: True # fails the check if the certificate is not valid yet (Optional)
                               # if True, the check will fail only if not_before is 0: if the certificate is not valid yet, but it is expected to be

FDG Example:
------------
main:
  description: 'ssl certificate check'
  module: ssl_certificate
  args:
    host_ip: 'www.google.com'
    host_port: 443
    ssl_timeout: 10 #seconds only honoured in case of ip and port
    path: /path/to/pem/file #Optional in place of host_ip, host_port

parameters:

    host_ip, host_port - A hostname (SSL endpoint to check) along with port is required if no file path is given

    path - Path of pem file containing SSL certificate. Only required if no endpoint (host, port) is provided

    ssl_timeout -  timeout value in seconds to be honoured only if host_ip, host_port is given - Default value - 3 seconds
Note:
    This module can be used in conjunction with osquery as the first module
    in the chain. Given that osquery fetches information about the open
    ports on a system and provides a 'host, port' tuple (or a list of host, port tuples)
    to this module, this module will connect to the host and port and fetch
    certificate details if a certificate is attached on the port. As an example,
    osquery needs to provide the value in the following format.
    +-------------------------------+-----------+
    | host_ip                       | host_port |
    +-------------------------------+-----------+
    | 127.0.0.1                     | 80        |
    | 2001:db8:85a3::8a2e:370:7334  | 80        |
    | 127.0.0.1                     | 443       |
    | 2001:db8:85a3::8a2e:370:7334  | 443       |
    +-------------------------------+-----------+

Comparator compatible with this module: certificate

Sample Output:
{
 "execution_time": 0.006193876266479492,
 "ssl_cert_pem": "-----BEGIN CERTIFICATE-----
                  abcdxyz
                  -----END CERTIFICATE-----\n",
 "ssl_cert_version": "2",
 "ssl_end_time": "2021-10-19 09:27:57",
 "ssl_has_expired": false,
 "ssl_issuer_common_name": "DigiCert SHA2 Secure Server CA",
 "ssl_serial_number": "1",
 "ssl_signature_algorithm": "sha256WithRSAEncryption",
 "ssl_src_host": "127.0.0.1",
 "ssl_src_port": "9100",
 "ssl_start_time": "2020-10-19 09:27:57",
 "ssl_subject_alternative_names": ["DNS:"],
 "ssl_subject_country": "US",
 "ssl_subject_organisation": "Adobe Systems Incorporated",
 "ssl_subject_organisation_unit": "IT"
 }
"""
import logging
import OpenSSL
import ssl
import time
from datetime import datetime
from socket import setdefaulttimeout

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': {'host_ip': '127.0.0.1',
                                                'host_port': 443},
                                    'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: ssl_certificate Start validating params for check-id: {0}'.format(block_id))

    error = {}
    chain_args = extra_args.get('chaining_args')
    endpoint_chained = runner_utils.get_chained_param(chain_args)
    if endpoint_chained:
        host_ip = endpoint_chained.get('host_ip')
        host_port = endpoint_chained.get('host_port')
    else:
        host_ip = runner_utils.get_param_for_module(block_id, block_dict, 'host_ip')
        host_port = runner_utils.get_param_for_module(block_id, block_dict, 'host_port')

    ssl_timeout = runner_utils.get_param_for_module(block_id, block_dict, 'ssl_timeout', 0)
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')

    endpoint_present = bool(host_ip and host_port)
    if not endpoint_present and not path:
        error['endpoint'] = 'Mandatory parameter: host_ip, host_port or path not found for id: %s' % (block_id)
    if endpoint_present and path:
        error[
            'endpoint'] = 'Only one of either endpoint data or path is required not both. Only one certificate per check for id: %s' % (
            block_id)

    if ssl_timeout < 0:
        error['ssl_timeout'] = 'Incorrect value provided for ssl_timeout'

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': {'host_ip': '127.0.0.1',
                                                'host_port': 443},
                                    'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    start_time = time.time()
    log.debug('Executing ssl_certificate module for id: {0}'.format(block_id))
    chain_args = extra_args.get('chaining_args') if extra_args else None
    endpoint_chained = runner_utils.get_chained_param(chain_args)
    if endpoint_chained:
        host_ip = endpoint_chained.get('host_ip')
        host_port = endpoint_chained.get('host_port')
    else:
        host_ip = runner_utils.get_param_for_module(block_id, block_dict, 'host_ip')
        host_port = runner_utils.get_param_for_module(block_id, block_dict, 'host_port')

    ssl_timeout = runner_utils.get_param_for_module(block_id, block_dict, 'ssl_timeout', 3)
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')

    cert = _get_cert(host_ip, host_port, ssl_timeout=ssl_timeout) if host_ip else _get_cert(path, from_file=True)
    if not cert:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unable_to_load_certificate')

    log.debug("ssl_certificate - cert found, parsing certificate")
    cert_details = _parse_cert(cert, host_ip, host_port, path)
    if 'error' in cert_details:
        log.debug('Error in parsing certificate. {0}'.format(cert_details['error']))
        return runner_utils.prepare_negative_result_for_module(block_id, 'unable_to_parse_certificate')
    stop_time = time.time()
    cert_details['execution_time'] = stop_time - start_time
    return runner_utils.prepare_positive_result_for_module(block_id, cert_details)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': {'host_ip': '127.0.0.1',
                                                'host_port': 443},
                                    'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))
    chain_args = extra_args.get('chaining_args') if extra_args else None
    endpoint_chained = runner_utils.get_chained_param(chain_args)
    if endpoint_chained:
        host_ip = endpoint_chained.get('host_ip')
        host_port = endpoint_chained.get('host_port')
    else:
        host_ip = runner_utils.get_param_for_module(block_id, block_dict, 'host_ip')
        host_port = runner_utils.get_param_for_module(block_id, block_dict, 'host_port')

    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    if path:
        return {'path': path}
    return {'host_ip': host_ip,
            'host_port': host_port}


def _get_cert(source, port=443, ssl_timeout=3, from_file=False):
    cert = _get_cert_from_file(source) if from_file else _get_cert_from_endpoint(source, port, ssl_timeout)
    return cert


def _get_cert_from_endpoint(server, port=443, ssl_timeout=3):
    try:
        log.debug("ssl_certificate is checking for ssl cert on {0}:{1}".format(server, port))
        hostport = (str(server), int(port))
        setdefaulttimeout(ssl_timeout)
        cert_details = ssl.get_server_certificate(hostport)
    except Exception as e:
        log.error('Unable to retrieve certificate from {0}. Error: {1}'.format(server, e))
        cert_details = None
    return cert_details


def _get_cert_from_file(cert_file_path):
    try:
        log.debug("ssl_certificate is checking for ssl cert from path {0}".format(cert_file_path))
        with open(cert_file_path) as cert_file:
            cert_details = cert_file.read()
    except IOError as e:
        log.error('File not found: {0}. Error: {1}'.format(cert_file_path, e))
        cert_details = None
    return cert_details


def _parse_cert(cert, host, port, path):
    """
    load the certificate using OpenSSL and parse needed params.
    """
    log.debug("Parsing the fetched certificate")
    cert_details = {}
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_details['ssl_src_port'] = str(port)
        cert_details['ssl_src_host'] = str(host)
        cert_details['ssl_src_path'] = str(path)
        if x509.get_issuer():
            issuer_components = _format_components(x509.get_issuer())
            cert_details['ssl_issuer_common_name'] = issuer_components.get('CN', "None")
        if x509.get_subject():
            subject_components = _format_components(x509.get_subject())
            cert_details['ssl_subject_country'] = subject_components.get('C', "None")
            cert_details['ssl_subject_organisation'] = subject_components.get('O', "None")
            cert_details['ssl_subject_organisation_unit'] = subject_components.get('OU', "None")
            cert_details['ssl_subject_common_name'] = subject_components.get('CN', "None")
        not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
        not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
        has_expired = x509.has_expired()
        cert_details['ssl_cert_version'] = str(x509.get_version())
        cert_details['ssl_has_expired'] = True if has_expired == 1 else False
        cert_details['ssl_serial_number'] = str(x509.get_serial_number())
        cert_details['ssl_end_time'] = str(not_after)
        cert_details['ssl_start_time'] = str(not_before)
        cert_details['ssl_signature_algorithm'] = str(x509.get_signature_algorithm())
        cert_details['ssl_cert_pem'] = str(cert)
        cert_details['ssl_subject_alternative_names'] = _get_certificate_san(x509)
    except Exception as e:
        cert_details['error'] = "An error occurred while parsing certificate - {0}".format(e)
    return cert_details


def _format_components(x509name):
    items = {}
    for item in x509name.get_components():
        items[item[0]] = item[1]
    return items


def _get_certificate_san(x509cert):
    san = ''
    trimmed_san_list = []
    try:
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        san_list = san.split(',')
        for san in san_list:
            trimmed_san = san.lstrip()
            trimmed_san_list.append(trimmed_san)
    except Exception as e:
        message = "ssl_certificate couldn't fetch SANs: {0}".format(e)
        log.error(message)
    return trimmed_san_list
