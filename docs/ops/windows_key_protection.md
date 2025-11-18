# Windows での鍵ファイル保護手順

BMSC v6 の鍵ファイル（例: `key_cli.bin`, `key_chat.bin`, `key_drive.bin`）を
Windows 上で安全に扱うための最小限の手順です。

---

## 1. 鍵ファイルの生成

PowerShell から 32 バイトの鍵を生成します。

```powershell
py - <<'PY'
import os; open('key_cli.bin','wb').write(os.urandom(32))
PY
```

必要に応じてファイル名を `key_chat.bin` や `key_drive.bin` に変えてください。

---

## 2. `icacls` で ACL を本人 + SYSTEM のみに固定

```powershell
$KEY = "key_cli.bin"

# 継承を切る（親フォルダからの権限を引き継がない）
icacls $KEY /inheritance:r

# 既存のアクセス権をリセットし、現在のユーザーにフル権限を付与
icacls $KEY /grant:r "$env:USERNAME":F

# SYSTEM にもフル権限を付与（バックアップ・ウイルス対策ソフトなどのため）
icacls $KEY /grant:r "SYSTEM":F

# 確認
icacls $KEY
```

ポイント:

- 他のユーザーやグループ（Users など）に権限が残っていないことを確認します。
- 同じ手順を `key_chat.bin`, `key_drive.bin` にも適用してください。

---

## 3. PowerShell + `Set-Acl` で同等の設定を行う例（任意）

`icacls` の代わりに、PowerShell の `Set-Acl` で近い設定を行う例です。

```powershell
$KEY = "key_cli.bin"

# 現在の ACL を取得
$acl = Get-Acl $KEY

# 継承を無効化し、継承された ACE を削除
$acl.SetAccessRuleProtection($true, $false)

# 現在のユーザーと SYSTEM にフルコントロールを付与
$ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, "FullControl", "Allow"
)
$ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow"
)

# 既存ルールをクリアしてから設定（必要に応じて調整）
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
$acl.AddAccessRule($ruleUser)
$acl.AddAccessRule($ruleSystem)

# ACL を書き戻す
Set-Acl -Path $KEY -AclObject $acl

# 確認
Get-Acl $KEY | Format-List
```

---

## 4. 運用ポリシー（まとめ）

- 本番では **`--key-file` で鍵ファイルを渡す** ことを前提とし、
  `--key-hex` や `--show-key` はローカル検証・デバッグ用途に限定します。
- 鍵ファイルは
  - Git などのバージョン管理には **絶対に入れない**
  - バックアップ時も暗号化済みストレージに保管する
- 鍵のローテーションを行う場合は、新しい鍵を同様の手順で生成・保護した上で、
  古い鍵を安全に削除してください。
