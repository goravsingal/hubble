# -*- encoding: utf-8 -*-
"""
Flexible Data Gathering
=======================

This module is designed to allow security engineers more flexibility in their
data gathering, without allowing arbitrary command execution from
hubblestack_data. You can think of it like a read-only, sandboxed shell.

It uses yaml files from hubblestack_data, and allows special fdg modules to be
chained together using pipes.

Data might look something like this::

    main:
        return: splunk_nova_return
        module: module_name.function
        args:
            - foo
            - bar
        kwargs:
            arg1: blah
            arg2: blah
        pipe:
            unique_id

    unique_id:
        module: module_name.function
        args:
            - foo
            - bar
        kwargs:
            arg1: blah
            arg2: blah
        xpipe:
            unique_id2

    unique_id2:
        module: module_name.function
        args:
            - foo
            - bar
        kwargs:
            arg1: test
            arg2: test

Each .yaml file contains a single fdg routine. ``main`` is a reserved id for
the entrypoint of the fdg routine. Chaining keywords such as ``pipe`` and
``xpipe`` both refer to other top-level ids in the file, and control the
execution control.

Here's a sample snippet with "names" for each of the parts::

    <id>:
        return: <returner_name>
        <module_name>.<function>:
            <keyword_arg_for_module>: <argument_value>
        <chaining_keyword>: <id>

In general, ``return`` should not be used, as returners can be handled in the
hubble scheduler. However, in some cases returners can be used within fdg
files. In this case, ``return`` is generally only be used on the ``main``
block, as you want to return the value when you're finished processing.
However, ``return`` can technically be used in any block, and when all chained
blocks under that block are done processing, the intermediate value will be
returned.

The ``<module_name>.<function>`` piece refers to fdg modules and the functions
within those modules. All public functions from fdg modules are available.

The fdg module functions must return a tuple of length two, with the first
value being the "status" of the run (which can be used by conditional chaining
keywords, see below) and the second value being the actual return value, which
will either be passed to chained blocks or returned back up the chain to the
calling block.

``<chaining_keywords>`` are the real flow control for the fdg routine. While
multiple chaining keywords can be used, only one will ever execute. Here is a
list of the supported chaining keywords, in order of precedence::

    pipe
    xpipe
    pipe_on_false
    pipe_on_true
    xpipe_on_false
    xpipe_on_true

Chaining keywords lower on the list take precedence over chaining keywords
higher on the list. Note that there are some exceptions -- for example,
chaining keywords ending in ``_on_true`` will only take precedence if the first
value returned from the module.function resolves to True in python.
``_on_false`` works similarly, though it works based on whether the value
resolves to False.  Otherwise it will be ignored, and the next precedence
chaining keyword will be executed.

You may have times where you want to use True/False conditionals to control
piping, but want to pass a value that's not restricted to True/False to the
the chained module. (Different lists, for example.) In this case, the module
should return a length-two tuple where the first value is the value to be used
for the conditional, and the second value is the value to be sent through the
chain.

``pipe`` chaining keywords send the whole value to the referenced fdg block.
The value is sent to the ``chained`` kwarg of the called module.function. All
public fdg module functions must accept this keyword arg.

``xpipe`` is similar to pipe, except that is expects an iterable value (usually
a list) and iterates over that value, calling the chained fdg block for each
value in the iteration. The results are put in a list, which is then returned.
The ``chained`` kwarg of the called module.function is the destination for
these ``xpipe`` values, same as with the ``pipe`` chaining keywords.

If there are no chaining keywords that are valid to execute, the fdg execution
will end and any ``return`` keywords will be evaluated as we move back up the
call chain.
"""

import logging
import os
import yaml

import hubblestack.extmods.module_runner.runner_factory as runner_factory

import salt.loader
import salt.utils
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)
__fdg__ = None
__returners__ = None
RETURNER_ID_BLOCK = None


def run(fdg_file, starting_chained=None):
    """
    Given an fdg file (usually a salt:// file, but can also be the absolute
    path to a file on the system), execute that fdg file, starting with the
    ``main`` block

    Returns a tuple, with the first item in that tuple being a two-item tuple
    with the fdg_file and the starting_chained value (dumped to a string),
    and the second item being the results::

        ((fdg_file, starting_chained), results)

    starting_chained
        Allows you to pass in a starting argument, which will be treated as
        the ``chained`` argument for the ``main`` block. Optional.
    """
    fdg_runner = runner_factory.get_fdg_runner()
    
    # initialize loader
    fdg_runner.init_loader()

    # Recursive execution of the blocks
    # Handover to fdg_runner
    return fdg_runner.execute(fdg_file, {
        'starting_chained': starting_chained
    })

def top(fdg_topfile='salt://fdg/top.fdg'):
    """
    fdg has topfile support, similar to audit, osquery, and fim support for
    topfiles.

    .. code-block:: yaml

        fdg:
          '*':
            - some_fdg_file
          'G@splunkindex:edgeteam':
            - extra_fdg_file: <starting_value>

    Each item in the list under a given match is a separate flexible data
    gathering routine. The ``.fdg`` filename should be left off, as periods
    in this context are interpreted as directory separators.

    Optionally, an fdg filename can be followed by a colon and a starting
    value (as shown above with ``extra_fdg_file``) which will be passed in
    as the ``starting_chained`` value.

    Note that all paths in this file are assumed to be under salt://fdg/

    Returns will be compiled into a dictionary. The keys are two-item tuples,
    the first of which is the fdg file, and the second of which is the
    (optional) ``starting_chained`` value dumped to a string. The values
    in the dictionary are the associated returns from the fdg runs.
    """
    fdg_routines = _get_top_data(fdg_topfile)

    ret = {}
    for fdg_file in fdg_routines:
        if isinstance(fdg_file, dict):
            for key, val in fdg_file.items():
                retkey, retval = fdg(_fdg_saltify(key), val)
                ret[retkey] = retval
        else:
            retkey, retval = fdg(_fdg_saltify(fdg_file))
            ret[retkey] = retval
    return ret


def _fdg_saltify(path):
    """
    Take a path as it would be formatted in the fdg topfile and convert
    it to a salt://fdg path.
    """
    os.path.sep.join(path.split('.'))
    return 'salt://fdg/{0}.fdg'.format(path)

def _get_top_data(topfile):

    cached_topfile = __salt__['cp.cache_file'](topfile)

    if not cached_topfile:
        log.debug('FDG topfile %s not found from fileserver. Aborting.', topfile)
        return []

    try:
        with open(cached_topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError('Could not load topfile: {0}'.format(exc))

    if not isinstance(topdata, dict) or 'fdg' not in topdata:
        raise CommandExecutionError('fdg topfile not formatted correctly: '
                                    'missing ``fdg`` key or not formed as a '
                                    'dict: {0}'.format(topdata))

    topdata = topdata['fdg']

    ret = []

    for match, data in topdata.items():
        if __salt__['match.compound'](match):
            ret.extend(data)

    return ret
