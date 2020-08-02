#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

from ansible.utils.display import Display
from ansible_collections.jr200.vault.plugins.module_utils.url import post


from os import environ, path

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
                               default=f"{environ['HOME']}/.vault-token")
    )

    result = dict(
        changed=False,
        failed='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    _get_token_info(module.params, result)

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if 'errors' in result:
        module.fail_json(msg='Failed to extract id of vault user.', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def _get_token_info(p, result):

    if not p['cached_token']:
        result['token_info'] = None
    elif not path.exists(p['cached_token_path']):
        result['token_info'] = None
    else:
        with open(p['cached_token_path'], 'rt') as fp:
            persisted_token = fp.read()

        token_info = post(
            "v1/auth/token/lookup",
            persisted_token,
            p['vault_addr'],
            p['vault_cacert'],
            {"token": persisted_token})

        if 'errors' in token_info:
            result['token_info'] = None
        else:
            result['persisted_token'] = persisted_token
            result['token_info'] = token_info


def main():
    run_module()


if __name__ == '__main__':
    main()
