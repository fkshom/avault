import pytest
from assertpy import assert_that, fail
import yaml
import logging
import avault.avault as avault
import io
import textwrap
import tempfile
import subprocess
import os
import sys
from pprint import pprint as pp

logger = logging.getLogger(__name__)

wholevault = textwrap.dedent("""
$ANSIBLE_VAULT;1.1;AES256
38383732363137313834383932643661656164646538646365653832613266313363653863653964
6262663164386136376133313162326434393865333261390a333336356562343935386539616533
61616537613536323366653063396530396136646537656465323863383365316338306430356365
6465613932396433300a376566663361313331366433393933313931386261383133393763636662
61333264366135613632616261313438366265656162643965663266646439373433303035346339
63636333356365363761643038626432373330393934663633326438623036326163636161366536
373662656362313831346230386331636464
""")[1:-1]

wholevault_decrypted = textwrap.dedent("""
- item1
- item2
- key1: value1
  key2:
    key2-2: value2-2
""")[1:-1]

vaulted_data = {}
vaulted_data['item2'] = """
          $ANSIBLE_VAULT;1.1;AES256
          37373634333632663932646537616437643631306634376638646437353239313334323465323630
          6536636263646430363862613436306433376637326539310a626362653835393632396639323038
          39353531363031313437633038653133393538646361323832333164623932646131616130633933
          6166636463353063330a343839333866343431383861353430623937363565383732323730363563
          3738
"""
vaulted_data['value2-2'] = """
          $ANSIBLE_VAULT;1.1;AES256
          37633532613764643434343431656236623036646137393433666338323237393662373533353433
          6230386361326632653265633232363738633663336565390a363331366633323339653863393036
          35313934643636663466306432323231323139313534333836386164323930363364633237626638
          3564363563383862660a356265343263373961656266383537313863616339646661656433633961
          3064
"""
inlinevault = textwrap.dedent(f"""
- item1
- item3
- !vault |
{vaulted_data['item2']}
- key1: value1
  key3: value3
  key2:
    key2-2: !vault |
{vaulted_data['value2-2']}
""")[1:-1]
print(inlinevault, file=sys.stderr)
inlinevault_decrypted = textwrap.dedent("""
- item1
- item3
- item2
- key1: value1
  key3: value3
  key2:
    key2-2: value2-2
""")[1:-1]

passwords = textwrap.dedent("""
#name1,password1
name2,test
""")

@pytest.fixture(scope='function', autouse=False)
def wholevaultfile():
    filename = '/tmp/abcde'
    with open(filename, 'w') as f:
        print(wholevault, end='', file=f)
    yield filename

@pytest.fixture(scope='function', autouse=False)
def stdinwholevault(monkeypatch):
    monkeypatch.setattr('sys.stdin', io.StringIO(wholevault))
    yield

@pytest.fixture(scope='function', autouse=False)
def inlinevaultfile():
    filename = '/tmp/abcde'
    with open(filename, 'w') as f:
        print(inlinevault, end='', file=f)
    yield filename

@pytest.fixture(scope='function', autouse=False)
def stdininlinevault(monkeypatch):
    monkeypatch.setattr('sys.stdin', io.StringIO(inlinevault))
    yield

@pytest.fixture(scope='function', autouse=False)
def passfile():
    passfile = '/tmp/passfile'
    with open(passfile, 'w') as f:
        print(passwords, end='', file=f)
    yield passfile

@pytest.fixture(scope='function', autouse=True)
def mock_decrypt_content_method():
    def _decrypt_content_mock(self, content, password):
        if content.strip() == wholevault.strip() and password == 'test':
            return wholevault_decrypted
        elif content.strip() == vaulted_data['item2'].replace(' ', '').strip() and password == 'test':
            return 'item2'
        elif content.strip() == vaulted_data['value2-2'].replace(' ', '').strip() and password == 'test':
            return 'value2-2'
        else:
            raise subprocess.CalledProcessError(returncode=1, cmd='ansible-vault')

    avault.AnsibleVault._decrypt_content_with_ansible_vault_command = _decrypt_content_mock
    yield


class Testサブコマンド機能試験():
    class Test_ecrypt():
        def test_ファイルが書き変わる(self, wholevaultfile, passfile):
            args = ['decrypt', '--passfile', passfile, wholevaultfile]
            avault.main(args=args)
            with open(wholevaultfile, 'r') as f:
                assert_that(f.read().rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    class Test_view():
        def test_stdoutに出力される(self, wholevaultfile, passfile, capfd):
            args = ['view', '--passfile', passfile, wholevaultfile]
            avault.main(args=args)
            out, err = capfd.readouterr()
            assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

class Test入力元別試験():
    def test_from_file(self, wholevaultfile, passfile):
        args = ['decrypt', '--passfile', passfile, wholevaultfile]
        avault.main(args=args)
        with open(wholevaultfile, 'r') as f:
            assert_that(f.read().rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    def test_from_stdin1(self, stdinwholevault, passfile, capfd):
        args = ['view', '--passfile', passfile]
        avault.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    def test_from_stdin2(self, stdinwholevault, passfile, capfd):
        args = ['view', '--passfile', passfile, '-']
        avault.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    def test_decrypt_deny_from_stdin(self, stdinwholevault, passfile, capfd):
        args = ['decrypt', '--passfile', passfile]
        with pytest.raises(SystemExit) as excinfo:
            avault.main(args=args)

class Test入力ファイル種類別試験():
    class Test_wholevaultfile():
        def test_wholevaultfile(self, wholevaultfile, passfile, capfd):
            args = ['view', '--passfile', passfile, wholevaultfile]
            avault.main(args=args)
            out, err = capfd.readouterr()
            assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    class Test_inlinevaultfile():
        def test_inlinevaultfile(self, inlinevaultfile, passfile, capfd):
            args = ['view', '--passfile', passfile, inlinevaultfile]
            avault.main(args=args)
            out, err = capfd.readouterr()
            assert_that(out.rstrip()).is_equal_to(inlinevault_decrypted.rstrip())


class Testパスワード入力方法():
    def test_ask_pass(self, wholevaultfile, monkeypatch, capfd):
        args = ['view', wholevaultfile]
        monkeypatch.setattr('getpass.getpass', lambda prompt: 'test')
        avault.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())
    
    def test_from_environment_variable(self, wholevaultfile, mocker, monkeypatch, capfd):
        args = ['view', wholevaultfile]
        mocker.patch('getpass.getpass', side_effect=Exception('Must not be called'))
        monkeypatch.setattr('os.environ', {'AVAULT_PASS': 'test'})
        avault.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    def test_with_pass_from_environment_variable_with_ask_pass(self, wholevaultfile, passfile, mocker, monkeypatch, capfd):
        args = ['view', '--passfile', passfile, wholevaultfile]
        monkeypatch.setattr('os.environ', {'AVAULT_PASS': 'test'})
        avault.main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())

class TestAnsible():
    def test_ansible(self):
        import ansible
        from ansible.parsing.vault import VaultLib
        def make_secrets(secret):
            from ansible.constants import DEFAULT_VAULT_ID_MATCH
            from ansible.parsing.vault import VaultSecret
            return [(DEFAULT_VAULT_ID_MATCH, VaultSecret(secret))]

        vault = VaultLib(make_secrets('test'.encode('utf-8')))

        plaintext = "text"
        assert_that(vault.decrypt(vault.encrypt(plaintext)).decode('utf-8')).is_equal_to(plaintext)
        plaintext = " text"
        assert_that(vault.decrypt(vault.encrypt(plaintext)).decode('utf-8')).is_equal_to(plaintext)
        plaintext = " text "
        assert_that(vault.decrypt(vault.encrypt(plaintext)).decode('utf-8')).is_equal_to(plaintext)
        plaintext = " text\n "
        assert_that(vault.decrypt(vault.encrypt(plaintext)).decode('utf-8')).is_equal_to(plaintext)
