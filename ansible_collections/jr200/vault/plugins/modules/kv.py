#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

from ansible_collections.jr200.vault.plugins.module_utils.url import get
from ansible.utils.vars import merge_hash

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = ""


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        vault_addr=dict(type='str', required=True),
        vault_cacert=dict(type='str', required=False, default=None),
        client_token=dict(type='str', required=True, no_log=True),
        kv_engine_path=dict(type='str', required=False, default='secret/data'),
        secret_path=dict(type='str', required=True),
        secret_version=dict(type='int', required=False, default=None),
        kv_version=dict(type='int', required=False, default=2),
        output_fact_name=dict(type='str', required=False, default=None),
    )

    result = dict(
        changed=False,
        failed='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    the_secret = _lookup_secret(module.params)

    result['changed'] = False
    result['secret_path'] = module.params['secret_path']
    result = merge_hash(result, the_secret)

    if 'errors' in result:
        module.fail_json(msg='Unable to retrieve secret.', **result)

    module.exit_json(**result)


def _lookup_secret(p):
    path = '/'.join([p['kv_engine_path'], p['secret_path']])
    if p['kv_version'] == 2 and p['secret_version']:
        path += u"?version=%s" % p['secret_version']

    return get(path,
               p['client_token'],
               p['vault_addr'],
               p['vault_cacert'],
               'secret')


def main():
    run_module()


if __name__ == '__main__':
    main()
