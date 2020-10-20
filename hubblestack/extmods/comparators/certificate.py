# -*- encoding: utf-8 -*-
"""
Certificate comparator used to compare SSL certificate fields

"compare" command example:

    comparator:
        type: certificate
        compare:
            not_before: 30 # maximum number of days until the certificate becomes valid (default value: 0)
                           # the check is failed if the certificate becomes valid in more than 30 days
            not_after: 45  # minimum number of days until expiration (default value: 0)
                           # the check is failed if the certificate expires in less than 45 days
            fail_if_not_before: True # fails the check if the certificate is not valid yet ( default value: False)
                           # if True, the check will fail only if not_before is 0 (or missing): if the certificate is not valid yet, but it is expected to be
                           
            ssl_issuer_common_name: 'DigiCert SHA2 Secure Server CA', (Optional)
            ssl_signature_algorithm: 'sha256WithRSAEncryption', (Optional)
            ssl_subject_country: 'US', (Optional)
            ssl_subject_organisation: 'Adobe Systems Incorporated', (Optional)
            ssl_subject_organisation_unit: 'IT' (Optional)

Note: Optional parameters are matched exactly. Currently there is no support for regex match for these params.
"""
import logging
from datetime import datetime

log = logging.getLogger(__name__)


def compare(audit_id, result_to_compare, args):
    """
    Compare the certificate fields
    :param audit_id:
            Check ID
    :param result_to_compare:
            Certificate data to compare
    :param args:
            Comparator dictionary as mentioned in check
    """
    log.debug('Running certificate::compare for check: {0}'.format(audit_id))
    if result_to_compare.get('ssl_has_expired', False):
        return False, "The certificate has expired"
    current_date = datetime.now().date()
    date_format = "%Y-%m-%d %H:%M:%S"

    cert_not_before = datetime.strptime(result_to_compare.get('ssl_start_time'), date_format).date()
    cert_not_after = datetime.strptime(result_to_compare.get('ssl_end_time'), date_format).date()
    not_before_to_compare = (cert_not_before - current_date).days
    not_after_to_compare = (cert_not_after - current_date).days

    not_before = args.get('compare').get('not_before', 0)
    not_after = args.get('compare').get('not_after', 0)
    fail_if_not_before = args.get('compare').get('fail_if_not_before', False)

    if not_before_to_compare > not_before:
        if not_before == 0 and fail_if_not_before:
            error_message = 'The certificate is not yet valid ({0} days left until it will be valid)'.format(
                not_before_to_compare)
            log.info(error_message)
            return False, error_message
        error_message = 'The certificate will be valid in more than {0} days'.format(not_before)
        log.info(error_message)
        return False, error_message

    if not_after_to_compare < not_after:
        error_message = 'The certificate will expire in less than {0} days'.format(not_after)
        log.info(error_message)
        return False, error_message

    completed_list = ['not_before', 'not_after', 'fail_if_not_before']

    for key in args.get('compare').keys():
        if key not in completed_list:
            if result_to_compare.get(key) != args.get('compare').get(key):
                log.debug('Value of field: {0} does not match. Expected value: {1}, Actual value: {2}'.format(key, args.get('compare').get(key), result_to_compare.get(key)))
                return False, 'Value does not match'

    return True, 'certificate_validation_passed'
