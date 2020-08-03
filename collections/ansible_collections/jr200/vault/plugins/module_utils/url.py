from ansible.module_utils._text import to_text
from ansible.module_utils.urls import open_url
from json import dumps, loads


def get(url_path, token, vault_addr, vault_cacert, response_name):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if token:
        headers['X-Vault-Token'] = token

    try:
        url = '/'.join([vault_addr, 'v1', url_path])
        response = open_url(url, None, headers, 'GET', ca_path=vault_cacert)
        return {response_name: loads(response.read().decode('utf-8'))}

    except Exception as e:
        return {'errors': to_text(e)}


def put(url_path, token, vault_addr, vault_cacert, cert_file=None, cert_key_file=None):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if token:
        headers['X-Vault-Token'] = 'true'

    try:
        url = '/'.join([vault_addr, 'v1', url_path])
        response = open_url(url, None, headers, 'PUT',
                            ca_path=vault_cacert,
                            client_cert=cert_file,
                            client_key=cert_key_file,
                            validate_certs=False)

        return loads(response.read().decode('utf-8'))

    except Exception as e:
        return {'errors': to_text(e)}


def post(url_path, token, vault_addr, vault_cacert, json_payload=None):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if token:
        headers['X-Vault-Token'] = token

    try:
        url = '/'.join([vault_addr, 'v1', url_path])
        response = open_url(url, dumps(json_payload), headers, 'POST',
                            ca_path=vault_cacert)

        return loads(response.read().decode('utf-8'))

    except Exception as e:
        return {'errors': to_text(e)}
