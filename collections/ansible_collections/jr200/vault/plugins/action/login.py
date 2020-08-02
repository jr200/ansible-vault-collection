from ansible.plugins.action import ActionBase
__metaclass__ = type

from ansible.utils.display import Display

from ansible.errors import AnsibleError

from ansible_collections.jr200.vault.plugins.module_utils.url import post
from ansible.utils.vars import merge_hash

from getpass import getpass
from os import environ, path
import sys
from json import dumps

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

        if args['cached_token']:
            whoami_args = {k: args[k] for k in ('cached_token', 'cached_token_path', 'vault_addr', 'vault_cacert')}
            whoami_response = self._execute_module("jr200.vault.whoami", module_args=whoami_args, tmp=tmp, task_vars=task_vars)

        # if a secret is not supplied, try to use the cached one, else prompt for it 
        # if a secret is supplied, always use it

        if not args['secret']:
            if args['cached_token'] and self._is_persisted_token_valid(args, whoami_response):
                args['secret'] = whoami_response['persisted_token']
                args['method'] = 'token'
            else:
                args['secret'] = self._prompt_for_secret(args)

        if 'ldap' == self._login_method:
            self.auth_ldap(args, result)
            result['changed'] = True
        elif 'token' == self._login_method:
            self.auth_token(args, result)
            result['changed'] = True
        else:
            raise AnsibleError("Failed to authenticate.")

        self._display.vvvv(dumps(result))

        if args['cached_token'] and 'failed' not in result:
            with open(args['cached_token_path'], 'wt') as fp:
                fp.writelines(result['client_token'])

        return result

    def _prompt_for_secret(self, p):
        if 'ldap' == p['method']:
            msg = f"Enter {p['method'].upper()} password for {p['username']}: "
        else:
            msg = f"Login {p['method'].upper()}: "

        prev_stdin = sys.stdin
        sys.stdin = open(self._stdin)
        secret = getpass(msg).strip()
        sys.stdin = prev_stdin
        return secret

    def _is_persisted_token_valid(self, p, token_info):
        try:
            if p['method'] == 'ldap':
                return p['username'] == token_info['data']['meta']['username']
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
