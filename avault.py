#!/usr/bin/env python3

import argparse
import subprocess
import tempfile
import os
import yaml
from pprint import pprint as pp
import sys


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

    def _decrypt_content(self, content, password):
        with tempfile.NamedTemporaryFile("w+") as f:
            print(password, file=f)
            f.seek(0)
            proc = subprocess.run(
                f'ansible-vault decrypt --vault-password-file {f.name} --output -',
                shell=True, check=True,
                input=content.strip(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return proc.stdout.strip()
 
    def _try_to_decrypt_content(self, content, password_sets):
        for password_set in password_sets:
            try:
                return self._decrypt_content(content, password_set['password'])        
                break
            except subprocess.CalledProcessError as e:
                pass
            except Exception as e:
                raise e
        else:
            raise Exception("Decrypt Error")

    def __init__(self, content, password_sets):
        self.content = content
        self.password_sets = password_sets

    def is_whole_vaulted(self):
        if self.content.strip().startswith("$ANSIBLE_VAULT"):
            return True
        return False

    def get_plain(self):
        if self.is_whole_vaulted():
            result = self._try_to_decrypt_content(content=self.content, password_sets=self.password_sets)
            return result
        else:
            # https://gihyo.jp/dev/serial/01/yaml_library/0003
            # https://stackoverflow.com/questions/27518976/how-can-i-get-pyyaml-safe-load-to-handle-python-unicode-tag
            # https://qiita.com/podhmo/items/aa954ee1dc1747252436
            def vault_constructor(loader, node):
                return self._try_to_decrypt_content(content=node.value, password_sets=self.password_sets)

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
            name, password = line.strip().split(',', 2)
            password_sets.append(dict(
                name=name, password=password
            ))
    return password_sets

def command_decrypt(args):
    password_sets = read_passfile(args.passfile)
    av = AnsibleVault.load(args.filename, password_sets)
    result = av.get_plain()
    with open(args.filename, 'w') as f:
        print(result, end='', file=f)
    return None

def command_view(args):
    password_sets = read_passfile(args.passfile)
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
