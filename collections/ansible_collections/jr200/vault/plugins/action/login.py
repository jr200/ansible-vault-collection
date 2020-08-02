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
        }

        args = merge_hash(args, self._task.args)
        self._stdin = args['secret_stdin']

        if args['cached_token']:
            token_lookup_args = {k: args[k] for k in ('cached_token', 'cached_token_path', 'vault_addr', 'vault_cacert')}
            token_lookup_response = self._execute_module("jr200.vault.token_lookup", module_args=token_lookup_args, tmp=tmp, task_vars=task_vars)

        # if a secret is not supplied, try to use the cached one, else prompt for it 
        # if a secret is supplied, always use it

        if not args['secret']:
            if args['cached_token'] and self._is_persisted_token_valid(args, token_lookup_response):
                args['secret'] = token_lookup_response['persisted_token']
                args['method'] = 'token'
            else:
                args['secret'] = self._prompt_for_secret(args)

        result = self._execute_module(module_args=args, tmp=tmp, task_vars=task_vars)

        return result

    def _prompt_for_secret(self, p):
        if 'ldap' == p['method']:
            msg = f"Enter {p['method'].upper()} password for {p['username']}: "
        else:
            msg = f"Login {p['method'].upper()}: "

        prev_stdin = sys.stdin
        sys.stdin = open(p['secret_stdin'])
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
