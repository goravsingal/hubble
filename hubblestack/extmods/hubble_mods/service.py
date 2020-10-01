# -*- encoding: utf-8 -*-
"""
Module for running stat command. Same can be used in both Audit/FDG

Audit Example:
---------------
check_id:
  description: 'sample description'
  tag: 'ADOBE-00041'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      module: service
      items:
        - args:
            name: 'abc*'
          comparator:
            type: "list"
            match_any:
              - name: abc2
                status: true
              - name: xyz
                status: false

FDG Example:
------------

main:
  description: 'service'
  module: service
  args:
    name: 'abc*'

Arg: name is an optional one. If called without any argument, it will list all services

Note: Comparison logic is moved to comparators. Module will just invoke the service command.
Comparator compatible with this module - list

Sample Output:
[
    {name: 'rsh', running: false, enabled: false},
    {name: 'abc', running: true, enabled: false}
    {name: 'xyz', running: true, enabled: true}
]
"""
import logging
import fnmatch

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)

def validate_params(block_id, block_dict, chain_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.debug('Module: service Start validating params for check-id: {0}'.format(block_id))

    #fetch required param
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name', chain_args)
    
    if not name:
        raise HubbleCheckValidationError('Mandatory parameter: {0} not found for id: {1}'.format('name', block_id))

    log.debug('Validation success for check-id: {0}'.format(block_id))

def execute(block_id, block_dict, chain_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing stat module for id: {0}'.format(block_id))

    #fetch required param
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name', chain_args)

    result = []
    matched_services = fnmatch.filter(__salt__['service.get_all'](), name)
    for matched_service in matched_services:
        service_status = __salt__['service.status'](matched_service)
        is_enabled = __salt__['service.enabled'](matched_service)
        result.append({
            "name": matched_service,
            "running": service_status,
            "enabled": is_enabled
        })

    return runner_utils.prepare_positive_result_for_module(block_id, result)

def get_filtered_params_to_log(block_id, block_dict, chain_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    #fetch required param
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name', chain_args)
    return {'name': name}
