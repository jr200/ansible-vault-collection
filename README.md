on macos:

https://bugs.python.org/issue33725
add this to .bash_profile
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES


## Collections

```
mkdir collections
ansible-galaxy collection init hashicorp.vault --init-path ./collections/ansible-collections
```

- try uploading to ansible galaxy
- cert login - need to execute this on remote machine
- kv write to file (on remote machine)
- kv - output fact (should be on remote machine)
- login - output fact (should be on remote machine)
- should slurp file from remote
- unseal
- /etc/sudoers.d/<username>
- antistrano for mtapps
- docker test - ca chain
- lookup plugin to retrieve secrets 
  - remember always runs on controller
  - always returns a list of items
- facts are cached 
  - maybe leaking credentials with kv?
  - read about cache plugin
- cert support
- 'output_fact_name': None


## Tips for writing modules/plugins
- set strategy to debug, (default is linear)

## References
https://www.ansible.com/blog/how-to-extend-ansible-through-plugins
https://docs.ansible.com/ansible/latest/dev_guide/developing_plugins.html#action-plugins
https://blog.artis3nal.com/2019-11-02-creating-a-custom-ansible-plugin/
https://bugs.python.org/issue33725
https://www.youtube.com/watch?v=CYghlf-6Opc