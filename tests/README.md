# tests

PowerShell 実行手順:

1) 実行ポリシーを一時緩和
   Set-ExecutionPolicy -Scope Process Bypass -Force

2) ラウンドトリップ・テストを実行
   .\tests\run_cli_roundtrip.ps1

上のスクリプトは、
- サンプルPDF生成
- 暗号化（.bmsc6 v2）
- 復号
- SHA256一致確認
まで自動で行います。
