# Infrastructure as Code

## Getting started

### Ansible setup

Python, PIP and Venv are assumed to be already installed. Do everything inside the `iac` folder. Then set up a blank virtual env and install ansible dependencies.

```
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Install collections

This installs ansible collections. SSH key auth must be set up with gitlab.

```
ansible-galaxy collection install -r requirements.yml
```

### Set up vault secret

Best practice is to store private data in encrypted ansible vault. Passing it every time via CLI is more secure but gets really annoying fast. I just tend to keep a strong password in `.ssh`. `vault.yml` is already locked with one such password. If you need access to IaC, put the value there.

### Set up authentication vault

Personal proxmox credentials cannot be committed into project, so setting it up is the first step. 

**When creating the vault, use the same password as given for main `vault.yml`, that makes it easy to unlock both using `--vault-password-file`.**

```
ansible-vault create credentials.yml --vault-password-file ~/.ssh/gitlab-runner-vault-nightly
```

Content will be your proxmox user-password combo **or** deploy token. Deploy permissions must be given by Sasho. Same goes for creating a token.

```
proxmox_user: username
proxmox_token_id: username
proxmox_token: something-something-something
```

This is also okay, proxmox playbooks support both.
```
proxmox_user: username
proxmox_pass: password
```

### Prepare SSH client for deployment

Ansible needs to SSH into newly created host after deploy, but it will block indefinitely on SSH client prompt. Easiest workaround is to simply disable strict key checking. SSH `User` is a nice to have but will let you log in after deploy as deploy user (not personal user added later). If the deploy user is changed in vars then it needs to be reflected here. Runner playbooks are set up to use `glr` which stands for *GitLab Runner*.

```
Host <ADDR>
  StrictHostKeyChecking no
  UserKnownHostsFile=/dev/null
  User glr
```

### Deploy it

This is minimal CLI to run gitlab runner deploy playbook. It assumes that user has little to no interest for ansible folder hierarchy and just wants to spin up few hosts with minimal hassle. Hence it omits proper stuff like `group_vars`, `host_vars`, `all.yml`, etc for basic variable file import. It also does not expect the user to write a single code of ansible, though some things are still needed.

* inventory.ini (could be yaml, but ini is more concise) - host and group definition, cannot be omitted since remote customization relies on group assignments, so even a single host needs inventory;
* `vars.yml` - all public variables go here, makes it easy to update stuff like CPU core count, RAM, disk space, etc without fiddling with encrypted vaults;
* `vault.yml` - here are gitlab runner tokens, admin user password, etc. Ideally modifying this is not needed, we only need to open it on deploy;
* `credentials.yml` - personal proxmox authentication goes here. File is in gitignore and will not be committed. **Use the same password as `vault.yml` to unlock both easily with one call;
* `--vault-password-file` - convenience, not needed. Alternatively use `-J` or `--ask-vault-password` and ansible will prompt for the password every time;

```
ansible-playbook -i inventory.ini qalab.gitlab.runners --extra-vars @vars.yml --extra-vars @vault.yml --extra-vars @credentials.yml --vault-password-file ~/.ssh/gitlab-runner-vault-nightly
```

### Nuke it

Ansible is not k8s. No declarative configuration management tool works as advertised. Gunk from old config will be left over and underneath the declarative syntax is imperative programming language using system tools. Don't reconfigure. Nuke the old and spin up new with updated config.

```
ansible-playbook -i inventory.ini qalab.proxmox.nuke --extra-vars @vars.yml --extra-vars @credentials.yml --vault-password-file ~/.ssh/gitlab-runner-vault-nightly
```
