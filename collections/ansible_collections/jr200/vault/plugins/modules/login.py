#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

from ansible_collections.jr200.vault.plugins.module_utils.url import post
from ansible.utils.vars import merge_hash
from ansible.errors import AnsibleError

from os import environ

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = ""


def run_module():

    module_args = dict(
        vault_addr=dict(type='str', required=True),
        vault_cacert=dict(type='str', required=False, default=None),
        cached_token=dict(type='bool', required=False, default=True),
        cached_token_path=dict(type='str', required=False,
                               default="%s/.vault-token" % environ['HOME']),
        method=dict(type='str', required=False, default='token'),
        username=dict(type='str', required=False, default=None),
        secret=dict(type='str', required=False, default=None, no_log=True),
        secret_stdin=dict(type='str', required=False, default='/dev/tty'),
    )

    result = dict(
        changed=False,
        failed='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if '__CACHED' == module.params['method']:
        auth_cached(module.params, result)
        result['changed'] = False
    elif 'LDAP' == module.params['method']:
        auth_ldap(module.params, result)
        result['changed'] = True
    elif 'USERPASS' == module.params['method']:
        auth_userpass(module.params, result)
        result['changed'] = True
    elif 'TOKEN' == module.params['method']:
        auth_token(module.params, result)
        result['changed'] = True
    else:
        raise AnsibleError("Failed to authenticate.")

    if module.params['cached_token'] and not result['failed']:
        with open(module.params['cached_token_path'], 'wt') as fp:
            fp.writelines(result['client_token'])

    if 'errors' in result:
        module.fail_json(msg='Failed to extract id of vault user.', **result)

    module.exit_json(**result)


def _login_did_error(response, result):
    if 'errors' in response:
        result['failed'] = True
        result = merge_hash(result, response)
        return True

    return False


def auth_ldap(p, result):
    response = post(
        "auth/ldap/login/%s" % p['username'],
        None,
        p['vault_addr'],
        p['vault_cacert'],
        json_payload={"password": p['secret']},
        )

    if not _login_did_error(response, result):
        result['client_token'] = response['auth']['client_token']


def auth_userpass(p, result):
    response = post(
        "auth/userpass/login/%s" % p['username'],
        None,
        p['vault_addr'],
        p['vault_cacert'],
        json_payload={"password": p['secret']},
        )

    if not _login_did_error(response, result):
        result['client_token'] = response['auth']['client_token']


def auth_token(p, result):
    response = post(
        "auth/token/create",
        p['secret'],
        p['vault_addr'],
        p['vault_cacert'])

    if not _login_did_error(response, result):
        result['client_token'] = response['auth']['client_token']


def auth_cached(p, result):
    result['client_token'] = p['secret']


def main():
    run_module()


if __name__ == '__main__':
    main()
