from ansible.plugins.action import ActionBase
__metaclass__ = type

from ansible.utils.vars import merge_hash

from getpass import getpass
from json import dumps
from os import environ
import sys


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)

        args = {
          'vault_addr': 'http://127.0.0.1:8200',
          'vault_cacert': None,
          'method': 'token',
          'username': environ['USER'],
          'secret': None,
          'secret_stdin': '/dev/tty',
          'cert_file': None,
          'cert_key_file': None,
          'cached_token': True,
          'cached_token_path': "%s/.vault-token" % environ['HOME'],
        }

        args = merge_hash(args, self._task.args)
        args['method'] = args['method'].upper()

        if args['cached_token']:
            lookup_args = {k: args[k] for k in ('cached_token', 'cached_token_path', 'vault_addr', 'vault_cacert')}
            lookup_result = self._execute_module("jr200.vault.lookup_self", module_args=lookup_args, tmp=tmp, task_vars=task_vars)
            self._display.vvvv("TOKEN_LOOKUP (module): %s" % dumps(lookup_result))

        # if a secret is supplied, always use it
        # else, try (i) use the cached one, (ii) prompt for the secret

        if not args['secret']:
            if args['cached_token'] and self._is_persisted_token_valid(args, lookup_result):
                args['secret'] = lookup_result['persisted_token']
                args['method'] = '__CACHED'

                # don't need to re-cache token
                args['cached_token'] = False
            else:
                args['secret'] = self._prompt_for_secret(args)

        result = self._execute_module(module_args=args, tmp=tmp, task_vars=task_vars)
        self._display.vvvv("LOGIN (module): %s" % dumps(args))

        return result

    def _prompt_for_secret(self, p):
        if p['method'] in {'LDAP', 'USERPASS'}:
            msg = "Enter %s password for %s: " % (p['method'], p['username'])
        elif p['method'] in {'TOKEN'}:
            msg = "Login %s: " % p['method']
        else:
            return None

        prev_stdin = sys.stdin
        sys.stdin = open(p['secret_stdin'])
        secret = getpass(msg).strip()
        sys.stdin = prev_stdin
        return secret

    def _is_persisted_token_valid(self, p, token_info):
        try:
            if token_info['token_info'] is None:
                return False

            found_path = token_info['token_info']['data']['path']

            if p['method'] == 'LDAP':
                return found_path == 'auth/ldap/login/%s' % p['username']

            if p['method'] == 'USERPASS':
                return found_path == 'auth/userpass/login/%s' % p['username']

            if p['method'] in {'CERT', 'TOKEN'}:
                # token-based logins are never persisted (opaqueness).
                # cert-based logins are not interactive - maybe should allow this still, but just fail?.
                return False
        except KeyError:
            pass

        return False
