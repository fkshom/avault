# avault

avaultは、ansible-vaultコマンドで暗号化されたファイルをview, decryptするコマンドラインアプリケーションです。
ansible-vaultコマンドとは異なる次の特徴を持ちます。
- 復号・表示専用（decrypt, viewサブコマンド）
- inline vaultファイルも復号・表示できる
- 複数のパスワードを入力し、総当たりで復号することが可能（パスワードを忘れた、複数のパスワードを扱っているなど）

## Usage

```sh
$ pip3 install avault
$ avault view vault.yml  # input password by prompt
$ avault view --passfile PASSFILE vault.yml
$ AVAULT_PASS=MYPASSWORD avault view vault.yml
```

```
avault {decrypt,view} [--passfile PASSFILE] [FILENAME]

--passfile PASSFILE: パスワード一覧ファイル。指定されない場合は、AVAULT_PASS環境変数か、プロンプトでパスワードを与える。
FILENAME: vaultファイル名。与えられない場合は標準入力から読み込む。
```

## PASSFILEフォーマット
```
password1
password2
```


