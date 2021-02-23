import argparse
import os
import subprocess
import tempfile
import yaml
from pprint import pprint as pp
import sys
from ansible.parsing.vault import VaultLib
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultSecret, AnsibleVaultError

class AnsibleVault():
    @classmethod
    def load(cls, filename, password_sets):
        content = None
        if filename == '-':
            content = sys.stdin.read()
        else:
            with open(filename, 'r') as f:
                content = f.read()
        return AnsibleVault(content, password_sets)

    def _decrypt_content_with_ansible_lib(self, content, password_sets):
        secrets = []
        for password_set in password_sets:
            password = password_set['password'].encode('utf-8')
            vaultid = password_set.get('name', DEFAULT_VAULT_ID_MATCH)
            secrets.append((vaultid, VaultSecret(password)))
        try:
            vault = VaultLib(secrets)
            return vault.decrypt(content).decode('utf-8')
        except Exception as e:
                raise e
        
    # Unused currently
    def _decrypt_content_with_ansible_vault_command(self, content, password_sets):
        for password_set in password_sets:
            password = (password_set['name'], password_set['password'])
            try:
                with tempfile.NamedTemporaryFile("w+") as f:
                    print(password, file=f)
                    f.seek(0)
                    proc = subprocess.run(
                        f'ansible-vault decrypt --vault-password-file {f.name} --output -',
                        shell=True, check=True,
                        input=content.strip(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    return proc.stdout.strip()     
            except subprocess.CalledProcessError as e:
                pass
            except AnsibleVaultError as e:
                pass
            except Exception as e:
                raise e
        else:
            raise Exception("Decrypt Error")

 
    def _try_to_decrypt_content(self, content, password_sets):
        return self._decrypt_content_with_ansible_lib(content, password_sets)

    def __init__(self, content, password_sets):
        self.content = content
        self.password_sets = password_sets

    def is_whole_vaulted(self):
        if self.content.strip().startswith("$ANSIBLE_VAULT"):
            return True
        return False

    def get_plain(self):
        if self.is_whole_vaulted():
            result = self._try_to_decrypt_content(content=self.content.strip(), password_sets=self.password_sets)
            return result
        else:
            # https://gihyo.jp/dev/serial/01/yaml_library/0003
            # https://stackoverflow.com/questions/27518976/how-can-i-get-pyyaml-safe-load-to-handle-python-unicode-tag
            # https://qiita.com/podhmo/items/aa954ee1dc1747252436
            def vault_constructor(loader, node):
                return self._try_to_decrypt_content(content=node.value.strip(), password_sets=self.password_sets)

            yaml.SafeLoader.add_constructor('!vault', vault_constructor)
            return yaml.dump(yaml.safe_load(self.content), sort_keys=False)

def read_passfile(passfile):
    password_sets = []
    with open(passfile) as f:
        for line in list(f.readlines()):
            if line.strip() == '':
                continue
            if line[0] == '#':
                continue
            columns = line.strip().split(',')
            if len(columns) == 1:
                password_sets.append(dict(
                    name=DEFAULT_VAULT_ID_MATCH, password=columns[0]
                ))
            elif len(columns) == 2:
                password_sets.append(dict(
                    name=columns[1], password=columns[0]
                ))
            else:
                print('passfile entry is invalid. columns length must be 1 or 2', file=sys.stderr)
    return password_sets

def read_passfile_(passfile):
    password_sets = []
    with open(passfile) as f:
        for line in list(f.readlines()):
            if line.strip() == '':
                continue
            if line[0] == '#':
                continue
            name, password = line.strip().split(',', 2)
            password_sets.append(dict(
                name=name, password=password
            ))
    return password_sets

def command_decrypt(args):
    if args.passfile:
        password_sets = read_passfile(args.passfile)
    elif os.environ.get('AVAULT_PASS'):
        password = os.environ['AVAULT_PASS']
        password_sets = [{'name':'default', 'password':password}]
    else:
        import getpass
        password = getpass.getpass(prompt='Password: ')
        password_sets = [{'mame':'default', 'password':password}]

    av = AnsibleVault.load(args.filename, password_sets)
    result = av.get_plain()
    with open(args.filename, 'w') as f:
        print(result, end='', file=f)
    return None

def command_view(args):
    if args.passfile:
        password_sets = read_passfile(args.passfile)
    elif os.environ.get('AVAULT_PASS'):
        password = os.environ['AVAULT_PASS']
        password_sets = [{'name':'default', 'password':password}]
    else:
        import getpass
        password = getpass.getpass(prompt='Password: ')
        password_sets = [{'mame':'default', 'password':password}]

    av = AnsibleVault.load(args.filename, password_sets)
    result = av.get_plain()
    print(result)
    return None

def main(args=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    
    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--passfile')
    parser_decrypt.add_argument('filename')
    parser_decrypt.set_defaults(handler=command_decrypt)

    parser_view = subparsers.add_parser('view')
    parser_view.add_argument('--passfile')
    parser_view.add_argument('filename', nargs='?', default='-')
    parser_view.set_defaults(handler=command_view)

    args = parser.parse_args(args)
    if hasattr(args, 'handler'):
        return args.handler(args)
    else:
        return parser.print_help()

if __name__ == "__main__":
    main()
