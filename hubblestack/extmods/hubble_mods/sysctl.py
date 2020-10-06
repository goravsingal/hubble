# -*- encoding: utf-8 -*-
"""
Module to check kernel parameters. Same can be used in both Audit/FDG

Audit Example:
---------------
check_unique_id:
  description: 'sysctl check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: sysctl
      items:
        - args:
            name: vm.zone_reclaim_mode

FDG Example:
------------
main:
  description: 'sysctl check'
  module: sysctl
  args:
    name: vm.zone_reclaim_mode

Mandatory parameters:
    name - name of kernel parameter
Multiple names can be provided in a single implementation under attribute: "items"

Note: Comparison logic is moved to comparators. Module will just invoke the sysctl command.
Comparator compatible with this module - dict

Sample Output:
{
'vm.mmap_rnd_compat_bits': '8',
'vm.nr_hugepages': '0',
'vm.nr_hugepages_mempolicy': '0',
'vm.nr_overcommit_hugepages': '0',
'vm.nr_pdflush_threads': '0',
'vm.numa_zonelist_order': 'default',
'vm.oom_dump_tasks': '1',
'vm.oom_kill_allocating_task': '0',
'vm.overcommit_kbytes': '0',
'vm.overcommit_memory': '0',
'vm.overcommit_ratio': '50',
'vm.page-cluster': '3',
'vm.panic_on_oom': '0',
'vm.percpu_pagelist_fraction': '0',
'vm.stat_interval': '1',
'vm.swappiness': '30',
'vm.user_reserve_kbytes': '117018',
'vm.vfs_cache_pressure': '100',
'vm.zone_reclaim_mode': '0'
}
"""

import logging

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
        Example: {'result': "vm.zone_reclaim_mode", 'status': True}

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.debug('Module: sysctl Start validating params for check-id: {0}'.format(block_id))

    error = {}
    name_param_chained = runner_utils.get_chained_param(chain_args)
    name_param = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    if not name_param_chained and not name_param:
        error['name'] = 'Mandatory parameter: name not found for id: %s' %(block_id)

    if error:
        raise HubbleCheckValidationError(error)

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
        Example: {'result': "vm.zone_reclaim_mode", 'status': True}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing sysctl module for id: {0}'.format(block_id))

    # fetch required param
    name = runner_utils.get_chained_param(chain_args)
    if not name:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    sysctl_res = __salt__['sysctl.get'](name)
    result = {name: sysctl_res}
    if not sysctl_res or "No such file or directory" in sysctl_res:
        return runner_utils.prepare_negative_result_for_module(block_id, "Could not find attribute %s in the kernel" %(name))
    if sysctl_res.lower().startswith("error"):
        return runner_utils.prepare_negative_result_for_module(block_id, "An error occurred while reading the value "
                                                                         "of kernel attribute %s" %(name))

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
        Example: {'result': "vm.zone_reclaim_mode", 'status': True}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    name = runner_utils.get_chained_param(chain_args)
    if not name:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    return {'name': name}
