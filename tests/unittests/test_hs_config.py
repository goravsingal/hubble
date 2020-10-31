#!/usr/bin/env python
# coding: utf-8

import os
import sys
import re
import copy
import json
import mock
import importlib
import pytest
import hubblestack.syspaths
import hubblestack.config
import hubblestack.daemon

import logging
log = logging.getLogger(__name__)

def intentionally_changed_value_filter(key_name, value, test_paths):
    if isinstance(value, (list,tuple)):
        if key_name.endswith('_dirs'):
            value = [ v for v in value if '/extmods/' not in v ]
        return [ intentionally_changed_value_filter(key_name, v, test_paths) for v in value ]
    if isinstance(value, dict):
        return { k: intentionally_changed_value_filter(k, v, test_paths) for k,v in value.items() }
    if isinstance(value, str):
        if test_paths is not None:
            # the jenkins workspace often contains '/hubble_PR-944/'
            # we have to be careful to not replace the beginning of that with
            # test_paths.sources
            value = re.sub(r'^/hubble\b', test_paths.sources, value)
        value = value.replace('/etc/salt/', '/etc/hubble/')
        value = value.replace('/var/cache/salt/', '/var/cache/hubble/')
        value = value.replace('/srv/salt/', '/srv/hubble/')
        value = value.replace('/hubble/minion/', '/hubble/')
        value = value.replace('/unittests/hubble.config', '/unittests/resources/test.config')
        value = value.replace('hubble/pki/minion', 'hubble/pki')
    return value

@pytest.fixture
def intentionally_removed_opts():
    return {
    "states_dirs",
    "render_dirs",
    "outputter_dirs",
    "auth_safemode",
    "auth_timeout",
    "auth_tries",
    "cluster_masters",
    "cluster_mode",
    "decrypt_pillar",
    "decrypt_pillar_default",
    "decrypt_pillar_delimiter",
    "decrypt_pillar_renderers",
    "enable_ssh_minions",
    "gather_job_timeout",
    "keysize",
    "master_roots",
    "master_shuffle",
    "master_tries",
    "pillar_roots",
    "random_master",
    "random_reauth_delay",
    "sign_pub_messages",
    "sock_dir",
    "sqlite_queue_dir",
    "ssh_config_file",
    "ssh_identities_only",
    "ssh_log_file",
    "ssh_merge_pillar",
    "ssh_passwd",
    "ssh_scan_ports",
    "ssh_scan_timeout",
    "ssh_sudo",
    "ssh_sudo_user",
    "ssh_timeout",
    "ssh_user",
    "syndic_event_forward_timeout",
    "syndic_jid_forward_cache_hwm",
    "transport",
    'decrypt_pillar',
    'decrypt_pillar_default',
    'decrypt_pillar_delimiter',
    'decrypt_pillar_renderers',
    'syndic_event_forward_timeout',
    'syndic_failover',
    'syndic_finger',
    'syndic_forward_all_events',
    'syndic_jid_forward_cache_hwm',
    'syndic_log_file',
    'syndic_master',
    'syndic_pidfile',
    'syndic_wait',
    'thorium_interval',
    'thorium_roots',
    'thorium_top',
    'thoriumenv',
    "winrepo_branch",
    "winrepo_cache_expire_max",
    "winrepo_cache_expire_min",
    "winrepo_cachefile",
    "winrepo_dir",
    "winrepo_dir_ng",
    "winrepo_insecure_auth",
    "winrepo_passphrase",
    "winrepo_password",
    "winrepo_privkey",
    "winrepo_pubkey",
    "winrepo_refspecs",
    "winrepo_remotes",
    "winrepo_remotes_ng",
    "winrepo_source_dir",
    "winrepo_ssl_verify",
    "winrepo_user",
    }

@pytest.fixture
def salt_config_opts(intentionally_removed_opts):
    """ computed-opts.json are the opts as generated by hubble's 4.1 branch
        at rev 88c4421 using the tests/unittests/conftest.py::__opts__, which
        itself uses tests/unittests/hubble.config

        There are certain things we never want to compare though, like the
        __cli (usually something like 'pytest' if this fixture is loading) and
        the key "grains" (which tells us a lot about the docker container, but
        doesn't compare very well and also isn't very relevant to this test.

        Because of the above, a few things in the orig-config.json are marked "!NO COMPARE!".
        If the key is also found on the __opts__ fixture (loaded from
        hubblestack.config); then we simply replace the new loaded value under
        that key with "!NO COMPARE!" also.  Strictly speaking "!NO COMPARE!"
        items are still compared in the sense that they have to exist in the
        new loaded config.

        We also keep a list of items intentionally removed from
        hubblestack.config that used to be in salt.config (e.g. raet and zmq
        settings). For these items, we have a simple fixture and we remove them
        from the orig_opts without checking to see if they're in the loaded
        opts. (Meaning we properly test to see that they're correctly missing
        in the actual test.)
    """

    with open('tests/unittests/resources/orig-config.json', 'r') as fh:
        dat = json.load(fh)
    for k in intentionally_removed_opts:
        if k in dat:
            del dat[k]
    return dat

@pytest.fixture
def modified_hs_config_opts(__opts__, salt_config_opts):
    opts = copy.deepcopy(__opts__) ## __opts__ is already a deepcopy, but for clarity, we'll leave this
    for k,v in salt_config_opts.items():
        if v == '!NO COMPARE!' and k in opts:
            opts[k] = v
    return opts

def test_new_hs_config_same_as_old_salt_config(modified_hs_config_opts,
        salt_config_opts, intentionally_removed_opts, test_paths):

    all_keys = set(modified_hs_config_opts).union(set(salt_config_opts))
    for key in all_keys:
        assert key not in intentionally_removed_opts
        assert key in modified_hs_config_opts
        assert key in salt_config_opts

        # construct mini dictionaries so if the comparison fails, one can
        # actually figure out where the failure occured.
        modified = { key: modified_hs_config_opts[key] }
        saltorig = { key: intentionally_changed_value_filter(key, salt_config_opts[key], test_paths) }
        assert modified == saltorig

CONF_DIR = os.path.join(os.path.dirname(__file__), 'resources')

# convince me this works:
@mock.patch('sys.platform', 'not linux')
def test_mock_platform():
    assert sys.platform == 'not linux'

def test_nomock_platform():
    assert sys.platform != 'not linux'

def _reload_hs_libs():
    importlib.reload(hubblestack.syspaths)
    importlib.reload(hubblestack.config)
    return hubblestack.config.DEFAULT_OPTS

@pytest.fixture(scope='function', autouse=True)
def cleanup(request, HSL):
    def inner_cleanup():
        _reload_hs_libs()
        # fix the HSL fixture (and all the __opts__/__mods__ it placed into the
        # various hubble modules)
        hubblestack.daemon.load_config(['-c', HSL.opts['conf_file']])
    request.addfinalizer(inner_cleanup)

def _both_platforms(opts, for_real=False):
    assert opts['log_level'] == 'error'
    assert opts['file_client'] == 'local'
    assert opts['fileserver_update_frequency'] == 43200  # 12 hours
    assert opts['grains_refresh_frequency'] == 3600  # 1 hour
    assert opts['scheduler_sleep_frequency'] == 0.5
    assert opts['default_include'] == 'hubble.d/*.conf'
    assert opts['logfile_maxbytes'] == 100000000  # 100MB
    assert opts['logfile_backups'] == 1  # maximum rotated logs
    assert opts['delete_inaccessible_azure_containers'] == False
    assert opts['enable_globbing_in_nebula_masking'] == False
    assert opts['osquery_logfile_maxbytes'] == 50000000  # 50MB
    assert opts['osquery_logfile_maxbytes_toparse'] == 100000000  # 100MB
    assert opts['osquery_backuplogs_count'] == 2

    if for_real:
        import hubblestack.daemon
        daemon_dir = os.path.dirname(hubblestack.daemon.__file__)
        daemon_forced_root = os.path.join(daemon_dir, 'files')
        opts['file_roots'] == {'base': daemon_forced_root}
    else:
        assert opts['file_roots'] == {'base': []}

@mock.patch('hubblestack.utils.platform.is_windows', lambda: False)
@mock.patch('sys.platform', 'linux')
def test_linux_paths():
    opts = _reload_hs_libs()
    assert opts['cachedir'] == '/var/cache/hubble'
    assert opts['pidfile'] == '/var/run/hubble.pid'
    assert opts['log_file'] == '/var/log/hubble'
    assert opts['osquery_dbpath'] == '/var/cache/hubble/osquery'
    assert opts['osquerylogpath'] == '/var/log/hubble_osquery'
    assert opts['osquerylog_backupdir'] == '/var/log/hubble_osquery/backuplogs'

    _both_platforms(opts)

@mock.patch('os.path._get_sep', lambda path: '\\')
@mock.patch('hubblestack.utils.platform.is_windows', lambda: True)
@mock.patch('sys.platform', 'WindersAmazingTechnology')
def test_winders_paths():
    opts = _reload_hs_libs()

    assert opts['cachedir'].lower() == r'c:\program files (x86)\hubble\var\cache'
    assert opts['pidfile'].lower() == r'c:\program files (x86)\hubble\var\run\hubble.pid'
    assert opts['log_file'].lower() == r'c:\program files (x86)\hubble\var\log\hubble.log'
    assert opts['osquery_dbpath'].lower() == r'c:\program files (x86)\hubble\var\hubble_osquery_db'
    assert opts['osquerylogpath'].lower() == r'c:\program files (x86)\hubble\var\log\hubble_osquery'
    assert opts['osquerylog_backupdir'].lower() == r'c:\program files (x86)\hubble\var\log\hubble_osquery\backuplogs'

    _both_platforms(opts)

@pytest.mark.skipif(sys.platform != 'linux', reason="")
def test_linux_for_real_kindof():
    opts = hubblestack.daemon.load_config(['-c', 'tests/unittests/resources/empty.config'])

    assert opts['cachedir'] == '/var/cache/hubble'
    assert opts['pidfile'] == '/var/run/hubble.pid'
    assert opts['log_file'] == '/var/log/hubble'
    assert opts['osquery_dbpath'] == '/var/cache/hubble/osquery'
    assert opts['osquerylogpath'] == '/var/log/hubble_osquery'
    assert opts['osquerylog_backupdir'] == '/var/log/hubble_osquery/backuplogs'

    _both_platforms(opts, for_real=True)
