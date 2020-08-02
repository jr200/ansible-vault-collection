#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

from ansible.utils.display import Display
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

display = Display()


def run_module():

    module_args = dict(
        vault_addr=dict(type='str', required=True),
        vault_cacert=dict(type='str', required=False, default=None),
        cached_token=dict(type='bool', required=False, default=True),
        cached_token_path=dict(type='str', required=False,
                               default=f"{environ['HOME']}/.vault-token"),
        method=dict(type='str', required=False, default='token'),
        username=dict(type='str', required=False, default=None),
        secret=dict(type='str', required=False, default=None),
        secret_stdin=dict(type='str', required=False, default='/dev/tty'),
        #   'output_fact_name': None
    )

    result = dict(
        changed=False,
        failed='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    login_method = module.params['method'].lower()
    if 'ldap' == login_method:
        auth_ldap(module.params, result)
        result['changed'] = True
    elif 'token' == login_method:
        auth_token(module.params, result)
        result['changed'] = True
    else:
        raise AnsibleError("Failed to authenticate.")

    if module.params['cached_token'] and 'failed' not in result:
        with open(module.params['cached_token_path'], 'wt') as fp:
            fp.writelines(result['client_token'])

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if 'errors' in result:
        module.fail_json(msg='Failed to extract id of vault user.', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def _login_did_error(response, result):
    if 'errors' in response:
        result['failed'] = True
        result = merge_hash(result, response)
        return True

    return False


def auth_ldap(p, result):
    response = post(
        f"v1/auth/ldap/login/{p['username']}",
        None,
        p['vault_addr'],
        p['vault_cacert'],
        payload={"password": p['secret']},
        )

    if not _login_did_error(response, result):
        result['client_token'] = response['auth']['client_token']


def auth_token(p, result):
    response = post(
        "v1/auth/token/create",
        p['secret'],
        p['vault_addr'],
        p['vault_cacert'])

    if not _login_did_error(response, result):
        result['client_token'] = response['auth']['client_token']


def main():
    run_module()


if __name__ == '__main__':
    main()
