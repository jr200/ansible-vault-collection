from ansible.module_utils._text import to_text
from ansible.module_utils.urls import open_url
from json import loads


def get(path, token, vault_addr, vault_cacert, response_name):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if token:
        headers['X-Vault-Token'] = token

    try:
        url = '/'.join([vault_addr, 'v1', path])
        response = open_url(url, None, headers, 'GET', ca_path=vault_cacert)
        return {response_name: loads(response.read().decode("utf-8"))}

    except Exception as e:
        return {"errors": to_text(e)}


def post(path, token, vault_addr, vault_cacert, payload=None):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if token:
        headers['X-Vault-Token'] = token

    try:
        url = '/'.join([vault_addr, path])
        response = open_url(url, payload, headers, 'POST',
                            ca_path=vault_cacert)
        return loads(response.read().decode("utf-8"))

    except Exception as e:
        return {"errors": to_text(e)}