from unittest import TestCase
import pytest
import mock

from hubblestack.extmods.hubble_mods import win_secedit
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinSecedit(TestCase):

    def test_get_filtered_params_to_log(self):
        """
        Check filtered logs output
        """
        sec_name = "PasswordHistorySize"
        block_id = "test_get_filtered_params_to_log"
        block_dict = {
                        "args":
                            {
                                "name": sec_name
                            }
                     }

        result = win_secedit.get_filtered_params_to_log(block_id, block_dict, extra_args=None)
        self.assertEquals(result.get("name"), sec_name)

    def test_validate_params_positive(self):
        """
        test validate params for positive result
        """
        sec_name = "PasswordHistorySize"
        block_id = "test_validate_params_positive"
        block_dict = {
                        "args" :
                            {
                                "name" : sec_name
                            }
                     }

        win_secedit.validate_params(block_id, block_dict)

    def test_validate_params_negative(self):
        """
        Test whether invalid input params will raise an exception or not.
        """
        sec_name = None
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": sec_name
                }
        }

        with pytest.raises(HubbleCheckValidationError) as exception:
            win_secedit.validate_params(block_id, block_dict, {})
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: name not found' in str(exception.value))

    def test_secedit_export(self):
        """
        Check whether the _secedit_export function return proper dict.
        """
        __secdata__ = {
                       'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel': '4,1',
                       'SeTakeOwnershipPrivilege': '*S-1-5-32-544'
                       }
        __salt__ = {}

        def cmd_run(cmd):
            return True

        def file_remove(file):
            return True

        __salt__['cmd.run'] = cmd_run
        __salt__['file.remove'] = file_remove
        win_secedit.__salt__ = __salt__
        win_secedit._secedit_import = mock.Mock(return_value=__secdata__)
        result = win_secedit._secedit_export()
        self.assertEquals(result, __secdata__)

    def test_get_account_sid(self):
        """
        Check whether the function _get_account_sid is able to convert 'accounts' into dict
        """
        accounts = "Name : Access Control Assistance Operators \n" \
                   "SID  : S-1-5-32-579"

        __salt__ = {}

        def cmd_run(cmd, shell='powershell', python_shell=True):
            return accounts
        __salt__['cmd.run'] = cmd_run
        win_secedit.__salt__ = __salt__
        result = win_secedit._get_account_sid()
        self.assertTrue(isinstance(result, dict))
        self.assertEquals(result.get("Access Control Assistance Operators"), "S-1-5-32-579")

    def test_execute_positive1(self):
        """
        sec_name present in __secdata__. Status is True, sec_value is equal to value in __secdata__
        """
        sec_name = "SeTakeOwnershipPrivilege"
        __secdata__ = {
                       'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel': '4,1',
                       'SeTakeOwnershipPrivilege': '*S-1-5-32-544'
                       }
        block_id = "test_execute1"
        block_dict = {
            "args":
                {
                    "name": sec_name
                }
        }
        win_secedit._secedit_export = mock.Mock(return_value=__secdata__)
        result = win_secedit.execute(block_id, block_dict, extra_args=None)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertTrue(isinstance(result[1].get('result').get('sec_value'), list))
        self.assertEquals(['*S-1-5-32-544'], result[1].get('result').get('sec_value'))

    def test_execute_positive2(self):
        """
        sec_name not present in __secdata__. Status is True, sec_value is 'No One'
        """
        sec_name = "SeBackupPrivilege"
        __secdata__ = {
                       'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel': '4,1',
                       'SeTakeOwnershipPrivilege': '*S-1-5-32-544'
                       }
        block_id = "test_execute2"
        block_dict = {
            "args":
                {
                    "name": sec_name
                }
        }
        win_secedit._secedit_export = mock.Mock(return_value=__secdata__)
        result = win_secedit.execute(block_id, block_dict, extra_args=None)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertTrue(isinstance(result[1].get('result').get('sec_value'), list))
        self.assertEquals(['No One'], result[1].get('result').get('sec_value'))

    def test_execute_positive3(self):
        """
        workflow when value_type is 'account'
        """
        sec_name = "SeTakeOwnershipPrivilege"
        __secdata__ = {
                       'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel': '4,1',
                       'SeTakeOwnershipPrivilege': '*S-1-5-32-544'
                       }
        block_id = "test_execute3"
        block_dict = {
            "args":
                {
                    "name": sec_name,
                    "value_type": "account"
                }
        }
        win_secedit._secedit_export = mock.Mock(return_value=__secdata__)
        win_secedit._get_account_name = mock.Mock(return_value=["administrator"])
        result = win_secedit.execute(block_id, block_dict, extra_args=None)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertTrue(isinstance(result[1].get('result').get('sec_value'), list))
        self.assertEquals(result[1].get('result').get('sec_value'), ["administrator"])

    def test_execute_positive4(self):
        """
        workflow when sec_name contains the string 'MACHINE'
        """
        sec_name = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel"
        __secdata__ = {
                       'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel': '4,1',
                       'SeTakeOwnershipPrivilege': '*S-1-5-32-544'
                       }
        block_id = "test_execute4"
        block_dict = {
            "args":
                {
                    "name": sec_name
                }
        }

        win_secedit._secedit_export = mock.Mock(return_value=__secdata__)
        win_secedit._reg_value_reverse_translator = mock.Mock(return_value=['Enabled', 'accept if provided by client'])
        result = win_secedit.execute(block_id, block_dict, extra_args=None)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertTrue(isinstance(result[1].get('result').get('sec_value'), list))
        self.assertTrue('Enabled' in result[1].get('result').get('sec_value'))