import pytest
from assertpy import assert_that, fail
import yaml
import logging
from avault import main
import avault
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
    30323633363634656636323338386264376561376632323135343964376332653431363132616365
    3762633064663266623361653264383761656462323334350a616361663938343865633033336334
    35343365656262666330613933633265326266633434313564303964663164366432666430363863
    6534313837316538310a333334646333613164306234326563633132343536366162306533386236
    3633
"""
vaulted_data['value2-2'] = """
            $ANSIBLE_VAULT;1.1;AES256
            39616165333162396239363165326434613731386531666336353435633131633139633634346130
            6230363165663034393561313937616233376439356233610a646539663731633939626366383237
            63656130313532633531383561313966666437383634646662363763303863303034643235613833
            6461626631613031330a626666343661666238353233353632363230393531316366303731666634
            3862
"""

inlinevault_ = textwrap.dedent("""
- item1
- item3
- !vault |
    $ANSIBLE_VAULT;1.1;AES256
    30323633363634656636323338386264376561376632323135343964376332653431363132616365
    3762633064663266623361653264383761656462323334350a616361663938343865633033336334
    35343365656262666330613933633265326266633434313564303964663164366432666430363863
    6534313837316538310a333334646333613164306234326563633132343536366162306533386236
    3633
- key1: value1
  key3: value3
  key2:
    key2-2: !vault |
            $ANSIBLE_VAULT;1.1;AES256
            39616165333162396239363165326434613731386531666336353435633131633139633634346130
            6230363165663034393561313937616233376439356233610a646539663731633939626366383237
            63656130313532633531383561313966666437383634646662363763303863303034643235613833
            6461626631613031330a626666343661666238353233353632363230393531316366303731666634
            3862
""")[1:-1]
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
name1,password1
name2,test
""")

class TestWholeVault():
    @pytest.fixture(scope='function', autouse=True)
    def scope_function(self):
        filename = '/tmp/abcde'
        with open(filename, 'w') as f:
            print(wholevault, end='', file=f)

        passfile = '/tmp/passfile'
        with open(passfile, 'w') as f:
            print(passwords, end='', file=f)

        def _decrypt_content_mock(self, content, password):
            if content.strip() == wholevault.strip() and password == 'test':
                return wholevault_decrypted
            else:
                raise subprocess.CalledProcessError(returncode=1, cmd='ansible-vault')

        avault.AnsibleVault._decrypt_content = _decrypt_content_mock
        yield dict(filename=filename, passfile=passfile)

    # @pytest.mark.skip(reason='pytestskip')
    def test_decrypt(self, scope_function):
        filename = scope_function['filename']
        passfile = scope_function['passfile']

        args = ['decrypt', '--passfile', passfile, filename]
        main(args=args)
        with open(filename, 'r') as f:
            assert_that(f.read().rstrip()).is_equal_to(wholevault_decrypted.rstrip())

    # @pytest.mark.skip(reason='pytestskip')
    def test_view(self, scope_function, capfd):
        filename = scope_function['filename']
        passfile = scope_function['passfile']

        args = ['view', '--passfile', passfile, filename]
        main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(wholevault_decrypted.rstrip())


class TestInlineVault():
    @pytest.fixture(scope='function', autouse=True)
    def scope_function(self):
        filename = '/tmp/abcde'
        with open(filename, 'w') as f:
            print(inlinevault, end='', file=f)

        passfile = '/tmp/passfile'
        with open(passfile, 'w') as f:
            print(passwords, end='', file=f)

        def _decrypt_content_mock(self, content, password):
            if content.strip() == vaulted_data['item2'].replace(' ', '').strip() and password == 'test':
                return 'item2'
            elif content.strip() == vaulted_data['value2-2'].replace(' ', '').strip() and password == 'test':
                return 'value2-2'
            else:
                raise subprocess.CalledProcessError(returncode=1, cmd='ansible-vault')

        avault.AnsibleVault._decrypt_content = _decrypt_content_mock
        yield dict(filename=filename, passfile=passfile)

    # @pytest.mark.skip(reason='pytestskip')
    def test_decrypt(self, scope_function):
        filename = scope_function['filename']
        passfile = scope_function['passfile']

        args = ['decrypt', '--passfile', passfile, filename]
        main(args=args)
        with open(filename, 'r') as f:
            assert_that(f.read().rstrip()).is_equal_to(inlinevault_decrypted.rstrip())

    # @pytest.mark.skip(reason='pytestskip')
    def test_view(self, scope_function, capfd):
        filename = scope_function['filename']
        passfile = scope_function['passfile']

        args = ['view', '--passfile', passfile, filename]
        main(args=args)
        out, err = capfd.readouterr()
        assert_that(out.rstrip()).is_equal_to(inlinevault_decrypted.rstrip())

