from ansible.plugins.action import ActionBase
__metaclass__ = type

from ansible.utils.display import Display

from ansible.errors import AnsibleError

from ansible_collections.jr200.vault.plugins.module_utils.url import post
from ansible.utils.vars import merge_hash

from getpass import getpass
from os import environ, path
import sys

display = Display()


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)

        args = {
          'vault_addr': 'http://127.0.0.1:8200',
          'vault_cacert': None,
          'method': 'token',
          'username': f"{environ['USER']}",
          'secret': None,
          'secret_stdin': '/dev/tty',
          'cached_token': True,
          'cached_token_path': f"{environ['HOME']}/.vault-token",
          'output_fact_name': None
        }

        args = merge_hash(args, self._task.args)
        self._login_method = args['method'].lower()
        self._stdin = args['secret_stdin']

        if self._try_get_persisted_token(args, result):
            pass
        elif 'ldap' == self._login_method:
            self.auth_ldap(args, result)
        elif 'token' == self._login_method:
            self.auth_token(args, result)
        else:
            raise AnsibleError("Failed to authenticate.")

        if args['cached_token'] and 'errors' not in result:
            with open(args['cached_token_path'], 'wt') as fp:
                fp.writelines(result['client_token'])

        return result

    def _prompt_for_secret(self, msg):
        prev_stdin = sys.stdin
        sys.stdin = open(self._stdin)
        secret = getpass(msg).strip()
        sys.stdin = prev_stdin
        return secret

    def _try_get_persisted_token(self, p, result):

        if not p['cached_token']:
            return False
        if not path.exists(p['cached_token_path']):
            return False

        with open(p['cached_token_path'], 'rt') as fp:
            persisted_token = fp.read()

        cache_response = post(
            "v1/auth/token/lookup",
            persisted_token,
            p['vault_addr'],
            p['vault_cacert'],
            {"token": persisted_token})

        if self._is_persisted_token_valid(p['username'], cache_response):
            result['client_token'] = persisted_token
            return True

        return False

    def _is_persisted_token_valid(self, username, cache_response):
        try:
            if self._login_method == 'ldap':
                return username == cache_response['data']['meta']['username']
        except (KeyError, TypeError):
            pass

        return False

    def _login_did_error(self, response, result):
        if 'errors' in response:
            result['failed'] = True
            result = merge_hash(result, response)
            return True

        return False

    def auth_ldap(self, p, result):

        if p['secret'] is None:
            p['secret'] = self._prompt_for_secret(
                f"Enter LDAP password for {p['username']}: ")

        response = post(
            f"v1/auth/ldap/login/{p['username']}",
            None,
            p['vault_addr'],
            p['vault_cacert'],
            payload={"password": p['secret']},
            )

        if not self._login_did_error(response, result):
            result['client_token'] = response['auth']['client_token']

    def auth_token(self, p, result):
        if p['secret'] is None:
            p['secret'] = self._prompt_for_secret("Enter Token: ")

        response = post(
            "v1/auth/token/create",
            p['secret'],
            p['vault_addr'],
            p['vault_cacert'])

        if not self._login_did_error(response, result):
            result['client_token'] = response['auth']['client_token']
