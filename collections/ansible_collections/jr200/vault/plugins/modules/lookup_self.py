#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

from ansible_collections.jr200.vault.plugins.module_utils.url import get

from os import environ, path

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
                               default="%s/.vault-token" % environ['HOME'])
    )

    result = dict(
        changed=False,
        failed='False',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    _get_token_info(module.params, result)

    if 'errors' in result:
        module.fail_json(msg='Failed to extract id of vault user.', **result)

    module.exit_json(**result)


def _get_token_info(p, result):

    if not p['cached_token']:
        result['token_info'] = None
    elif not path.exists(p['cached_token_path']):
        result['token_info'] = None
    else:
        with open(p['cached_token_path'], 'rt') as fp:
            persisted_token = fp.read()

        token_info = get(
            "auth/token/lookup-self",
            persisted_token,
            p['vault_addr'],
            p['vault_cacert'],
            "token_info"
            )

        if 'errors' in token_info:
            result['errors'] = token_info['errors']
        else:
            result['persisted_token'] = persisted_token
            result['token_info'] = token_info['token_info']


def main():
    run_module()


if __name__ == '__main__':
    main()
