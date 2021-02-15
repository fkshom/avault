#!/usr/bin/env python3

import argparse
import subprocess
import tempfile
import os
import yaml
from pprint import pprint as pp

class AnsibleVault():
    def __init__(self, filename, password_sets):
        self.filename = filename
        self.password_sets = password_sets

    def is_whole_vaulted(self):
        with open(self.filename, 'r') as f:
            if f.readline().strip().startswith("$ANSIBLE_VAULT"):
                return True
        return False

    def _run_process(self, command):
        for password_set in self.password_sets:
            try:
                with tempfile.NamedTemporaryFile("w+") as f:
                    print(password_set['password'], file=f)
                    f.seek(0)
                    subprocess.run(f'ansible-vault {command} --vault-password-file {f.name} {self.filename}', shell=True, check=True)
                    break
            except subprocess.CalledProcessError as e:
                pass
            except Exception as e:
                raise e
        else:
            raise Exception("Decrypt Error")

    def decrypt(self):
        if self.is_whole_vaulted():
            self._run_process(command='decrypt')
        else:
            raise Exception(f"{self.filename} is not whole vaulted file. decrypt subcommand does not support.")

    def view(self):
        if self.is_whole_vaulted():
            self._run_process(command='view')
        else:
            raise Exception(f"{self.filename} is not whole vaulted file. view subcommand does not support.")

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


# https://gihyo.jp/dev/serial/01/yaml_library/0003
# https://stackoverflow.com/questions/27518976/how-can-i-get-pyyaml-safe-load-to-handle-python-unicode-tag
# https://qiita.com/podhmo/items/aa954ee1dc1747252436
def yaml_register_class(klass, ytag):
    # suffix = '%s.%s' % (klass.__module__, klass.__name__)
    # def representer(dumper, instance):
    #     node = dumper.represent_mapping(ytag, instance.__dict__)
    #     return node
    def constructor(loader, node):
        av = AnsibleVault(string=node.value, password_sets=password_sets)
        return node.value
    # yaml.SafeDumper.add_representer(klass, representer)
    yaml.SafeLoader.add_constructor(ytag, constructor)
    #suffix = '%s.%s' % (klass.__module__, klass.__name__)
    #f1 = lambda dumper, obj: dumper.represent_mapping(ytag, obj.__dict__)
    #f2 = lambda loader, node: loader.construct_python_object(suffix, node)
    #yaml.add_representer(klass, f1)
    #yaml.add_constructor(ytag, f2)

class VaultString():
    def __init__(self, str):
        self.str = 'unko'

    def __str__(self) -> str:
        return self.str

def command_decrypt_yaml(args):
    password_sets = read_passfile(args.passfile)
    #yaml_register_class(VaultString, '!vault')

    def constructor(loader, node):
        av = AnsibleVault(string=node.value, password_sets=password_sets)
        return av.view()
    yaml.SafeLoader.add_constructor('!vault', constructor)

    with open(args.filename, 'r') as f:
        obj = yaml.safe_load(f)
        pp(obj)

def command_decrypt(args):
    password_sets = read_passfile(args.passfile)
    av = AnsibleVault(args.filename, password_sets)
    av.decrypt()

def command_view(args):
    password_sets = read_passfile(args.passfile)
    av = AnsibleVault(args.filename, password_sets)
    av.view()

def main(args=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    
    parser_decrypt = subparsers.add_parser('decrypt_yaml')
    parser_decrypt.add_argument('--passfile')
    parser_decrypt.add_argument('filename')
    parser_decrypt.set_defaults(handler=command_decrypt_yaml)

    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--passfile')
    parser_decrypt.add_argument('filename')
    parser_decrypt.set_defaults(handler=command_decrypt)

    parser_view = subparsers.add_parser('view')
    parser_view.add_argument('--passfile')
    parser_view.add_argument('filename')
    parser_view.set_defaults(handler=command_view)

    args = parser.parse_args(args)
    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
