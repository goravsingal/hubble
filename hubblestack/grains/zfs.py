# -*- coding: utf-8 -*-
'''
ZFS grain provider

:maintainer:    Jorge Schrauwen <sjorge@blackdot.be>
:maturity:      new
:platform:      illumos,freebsd,linux

.. versionadded:: 2018.3.0

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging

# Import salt libs
import hubblestack.utils.dictupdate
import hubblestack.utils.path
import hubblestack.utils.platform

# Solve the Chicken and egg problem where grains need to run before any
# of the modules are loaded and are generally available for any usage.
import hubblestack.modules.cmdmod
import hubblestack.utils.zfs

__virtualname__ = 'zfs'
__salt__ = {
    'cmd.run': hubblestack.modules.cmdmod.run,
}
__utils__ = {
    'zfs.is_supported': hubblestack.utils.zfs.is_supported,
    'zfs.has_feature_flags': hubblestack.utils.zfs.has_feature_flags,
    'zfs.zpool_command': hubblestack.utils.zfs.zpool_command,
    'zfs.to_size': hubblestack.utils.zfs.to_size,
}

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Load zfs grains
    '''
    # NOTE: we always load this grain so we can properly export
    #       at least the zfs_support grain
    #       except for Windows... don't try to load this on Windows (#51703)
    if hubblestack.utils.platform.is_windows():
        return False, 'ZFS: Not available on Windows'
    return __virtualname__


def _zfs_pool_data():
    '''
    Provide grains about zpools
    '''
    grains = {}

    # collect zpool data
    zpool_list_cmd = __utils__['zfs.zpool_command'](
        'list',
        flags=['-H'],
        opts={'-o': 'name,size'},
    )
    for zpool in __salt__['cmd.run'](zpool_list_cmd, ignore_retcode=True).splitlines():
        if 'zpool' not in grains:
            grains['zpool'] = {}
        zpool = zpool.split()
        grains['zpool'][zpool[0]] = __utils__['zfs.to_size'](zpool[1], False)

    # return grain data
    return grains


def zfs():
    '''
    Provide grains for zfs/zpool
    '''
    grains = {}
    grains['zfs_support'] = __utils__['zfs.is_supported']()
    grains['zfs_feature_flags'] = __utils__['zfs.has_feature_flags']()
    if grains['zfs_support']:
        grains = hubblestack.utils.dictupdate.update(grains, _zfs_pool_data(), merge_lists=True)

    return grains

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
