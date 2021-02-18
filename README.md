# avault

avaultは、ansible-vaultコマンドで暗号化されたファイルをview, decryptするコマンドラインアプリケーションです。
ansible-vaultコマンドとは異なる次の特徴を持ちます。
- 復号・表示専用（decrypt, viewサブコマンド）
- inline vaultファイルも復号・表示できる
- 複数のパスワードを入力し、総当たりで復号することが可能（パスワードを忘れた、複数のパスワードを扱っているなど）

## Usage

```sh
$ wget https://github.com/fkshom/avault/raw/main/avault
$ chmod +x ./avault
$ ./avault view --passfile passwords.txt vault.yml
```

```
avault {decrypt,view} [--passfile PASSFILE] [FILENAME]

--passfile PASSFILE: パスワード一覧ファイル。指定されない場合は、AVAULT_PASS環境変数か、プロンプトでパスワードを与える。
FILENAME: vaultファイル名。与えられない場合は標準入力から読み込む。
```

## PASSFILEフォーマット
```
name1,password1
name2,password2
```
nameは、識別子。任意の文字列。

