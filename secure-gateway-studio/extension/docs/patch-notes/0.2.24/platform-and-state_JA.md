# Secure Gateway Studio 0.2.24 パッチノート — Teardown、CEP、証明書、永続状態

Teardown と手動削除、Chrome Enterprise Premium、証明書と Chrome Root Store、暗号化と監査。

累積パッチノート [`PATCH_NOTES_0.2.24_JA.md`](../../PATCH_NOTES_0.2.24_JA.md) の一部である。全体の索引、リリース概要、版別の経緯はそちらを参照すること。

---

## Teardown と手動削除

- Teardown 前に run-owned resource だけから不変プランを作る
- plan hash に対応する正確な確認文を要求する
- shared／unowned resource は削除対象にしない
- IAM は記録済み before-image と managed-after が一致する場合だけ復元する
- response-lost や drift がある場合は所有権を残し、成功を推測しない
- Teardown の進捗と失敗を IndexedDB へ保存する
- 中断した Teardown は同じ teardown ID で再開する

検証環境では、Secure Gateway Studio が作成したリソースを一度すべて削除した。対象には VM、boot disk、VPC、subnet、Router、Cloud NAT、firewall、内部 IP、Cloud DNS、Secret Manager、BeyondCorp Gateway、サービスアカウント、カスタムロール、プロジェクト IAM、Access Policy IAM が含まれる。

削除時は、名前の部分一致でプロジェクト全体を消さず、確認済みの Secure Gateway Studio 所有対象だけに限定した。既存 Access Level、無関係な CEP ロール、無関係な Chrome 用サービスアカウントは残した。削除後に再認証し、GCP 側が空であることを確認した。

## Chrome Enterprise Premium

### CEP 画面

- Chrome Policy、Access Level、Cloud Identity DLP、OU、ライセンスのモジュールを分けた
- 選択したモジュールだけを適用する
- OU 一覧を取得できない場合は変更を始めない
- root-first の OU 一覧を自動選択しない
- OU ID と現在の完全な OU path を直前に確認する
- 子 OU 作成は明示チェックがある場合だけ行う
- 適用済みと skipped を画面に分けて表示する
- rollback 前に確認ダイアログを表示する

### DLP マトリクス

- upload、download、paste、print、watermark を行列で設定できる
- 公開 Chrome Policy API が対応する `warnUser` と `blockContent` だけを送る
- 未対応の BYOD 条件や `auditOnly` を推測した CEL で作らない
- アクセスレベル条件は Admin console で設定する必要があると表示する
- preset を Recommended、Strict Zero Trust、GenAI Secure、Warning First として整理した

### OU ライセンス割り当て

PoC の誤課金を避けるため、ライセンス割り当てを次の範囲に制限した。

- 選択 OU の直下ユーザーだけ
- 子 OU は除外
- 重複を除いた最大 10 名
- Directory API は最大 4 ページまで
- 全ユーザー一覧を取得し終わる前に 1 件目を割り当てない
- 10 名超過、ページ超過、空、不完全、タイムアウト時はライセンス変更 0 件
- Directory と Licensing の各要求は 5 秒で timeout
- デプロイヤー同一性の確認はルート全体で 10 秒
- POST 応答を失った場合は product、SKU、user の完全一致 GET で照合する
- 結果不明なら durable tenant／OU lease を保持する

## 証明書と Chrome Root Store

- local PoC CA、Enterprise CA、public trust の証明書戦略を分けた
- 秘密鍵は active Run 中の `chrome.storage.session` にだけ保持する
- 秘密鍵を IndexedDB、`chrome.storage.local`、ログ、ダウンロードへ保存しない
- 公開 root CA だけをダウンロード対象にする
- Chrome Admin console の `Chrome > Connectors > Chrome Root Store` へ登録する手順をガイド化した
- 証明書 SAN、TLS version、trust mode、HTTP response を acceptance evidence として記録する
- Enterprise CA の CSR と鍵生成 intent を checkpoint し、response-lost を照合する
- 所有する証明書だけを disable／revoke する

## 永続状態と監査

### 暗号化

- IndexedDB に保存する deployment、tenant、identity、audit を AES-256-GCM で暗号化する
- データ鍵は non-extractable とし、IndexedDB の structured clone で worker restart を越える
- schema、store、record の対応を AAD に含める
- 鍵の欠落、差し替え、ciphertext 改ざんを fail-closed にする
- locale 以外の setup／workflow を平文 localStorage に保存しない

### 0.2.0 データ移行

- `onupgradeneeded` や cold start で旧 tenant data を勝手に読まない
- 最初の利用開示を承認するまで旧 IndexedDB、`chrome.storage.local`、setup、workflow を検査しない
- 同意後に旧値を暗号化して移行する
- 平文の setup／workflow を消してから同意完了にする

### 監査と証拠

- approval、Apply、resume、rollback、Teardown、CEP、operator acceptance の actor を Google の確認済み ID へ固定する
- audit event を SHA-256 chain にする
- chain head、Run、acceptance、audit event を JSON evidence bundle として出力する
- T01～T09 の acceptance matrix を UI から確認できる
- URL path、query、IP、principal、自由形式ログ payload を通常の証拠一覧へ過剰保存しない
- Gateway の完全な接続ログは利用者の Google Cloud Logging に残し、開発者へ送らない
