# Secure Gateway Studio 0.2.24 パッチノート — デプロイと実行

デプロイヤー bootstrap、Google Cloud API と権限、preflight と承認、Apply、再開とロールバック。

累積パッチノート [`PATCH_NOTES_0.2.24_JA.md`](../../PATCH_NOTES_0.2.24_JA.md) の一部である。全体の索引、リリース概要、版別の経緯はそちらを参照すること。

---

## デプロイヤー bootstrap

### キーレス認証

- Google Cloud の初回準備だけは、明示確認後に現在の管理者権限を使う
- 専用サービスアカウント、製品用途限定カスタムロール、Token Creator、プロジェクト IAM、Access Policy IAM を構成する
- bootstrap 完了後の Google Cloud 変更は、固定したデプロイヤーの短期 impersonation token だけを使う
- 管理者トークンへ暗黙にフォールバックしない
- 長期サービスアカウントキーを作らない

### 0.2.0 デプロイヤー移行

`No 0.2.0 deployer identity is stored locally for explicit migration` で停止した問題を修正した。

0.2.0 はデプロイヤーのメールアドレスしか保存しておらず、拡張機能の再インストールや状態移行後は、そのヒント自体がなくなる場合がある。0.2.24 までの移行処理は、ローカルヒントだけを移行根拠にしない。

- 対象を製品が予約した 2 つのサービスアカウント名に限定する
- Google Cloud から不変数値 ID を読み取る
- ユーザー管理キーが存在しないことを確認する
- カスタムロールの title、description、stage、権限集合を完全比較する
- サービスアカウント IAM の唯一の Token Creator が現在の操作者であることを確認する
- プロジェクト IAM が 0.2.0 の厳密な許可リストと一致することを確認する
- Access Policy IAM も確認する
- 1 項目でも差異があれば、移行も権限付与も行わず停止する
- 利用者が `MIGRATE_EXISTING_DEPLOYER` を専用確認で承認した場合だけ移行する

厳密な移行監査に失敗した場合は、旧デプロイヤーを変更しない。利用者がもう一度承認した場合だけ、別の予約名を使う分離デプロイヤーを作成する。

### 同一操作者の判定

同じ Google アカウントを使っているのに、次のメッセージで再開できなかった問題を修正した。

- `The current operator or deployer identity differs from the interrupted run.`
- `The signed-in Google account differs from the operator who approved this run.`

0.2.0 は `approvedBy` にサービスアカウントのメールアドレスを入れていたため、人間の操作者と比較すると必ず不一致になった。現在は次の情報を分けて保持する。

- Google が確認した人間のメールアドレス
- OpenID Connect の不変 `sub`
- デプロイヤーサービスアカウントのメールアドレス
- デプロイヤーサービスアカウントの不変数値 ID
- 対象プロジェクト
- 承認時の構成ハッシュ

古い Run の再開では、0.2.0 の誤った `approvedBy` を履歴として残し、別の監査済み human binding を作る。メールアドレスだけを見て同一人物と決める処理にはしていない。

### 削除済みデプロイヤーの再作成

0.2.24 で、次のエラー専用の復旧経路を追加した。

`The pinned deployer service account no longer exists. Review the deletion and migrate explicitly before bootstrap.`

通常のサインアウトや初期化では、デプロイヤーの所有権 pin を消さない。これは、同じメールアドレスで作り直した別のサービスアカウントを自動採用しないためである。再作成は次の手順で行う。

1. 通常 bootstrap を読み取り専用で実行し、固定 SA の 404 を確認する。
2. UI が削除専用の確認文を表示する。
3. 利用者が承認すると、同じ操作者か再確認する。
4. カスタムロール、プロジェクト IAM、Access Policy IAM を監査する。
5. 実行中の Apply、Teardown、CEP lease がないことを確認する。
6. 旧 pin の完全な SHA-256、旧数値 ID、ロール、操作者を tombstone として保存する。
7. 新しいサービスアカウント作成 intent を永続化してから Google API を呼ぶ。
8. 削除済みカスタムロールが残っていれば、完全な定義と etag を確認して undelete する。
9. 新しい SA の Token Creator、プロジェクト IAM、Access Policy IAM を構成する。
10. 新しい不変数値 ID を pin し、復旧用マーカーを消す。

tombstone はプロジェクトごとに新しい 8 件まで保持する。旧 ID を復活させる用途には使わず、どの固定情報を廃止したかを監査するために使う。

### 途中停止への対応

削除済みデプロイヤーの復旧中に service worker が停止しても、次の状態から再開できる。

- 旧 pin を廃止した直後
- SA 作成 intent を保存した直後
- 新しい SA を作成し、カスタムロールをまだ復元していない状態
- カスタムロールの undelete 応答を受け取れなかった状態
- プロジェクト IAM は付与済みだが Access Policy IAM が失敗した状態

途中状態では、旧数値 ID と削除済みロールの証跡を新しい pin に一時保存する。すべての権限付与と再監査が完了するまで、この証跡を消さない。

## Google Cloud API と権限

### Regional Health Check

`compute.regionHealthChecks.get` がなく、Option B の health check を検出できなかった問題を修正した。

- `compute.regionHealthChecks.get`
- `compute.regionHealthChecks.create`
- `compute.regionHealthChecks.delete`

上記を拡張機能版デプロイヤーの完全なカスタムロール定義へ追加した。グローバル `compute.healthChecks.*` だけでは Regional Health Check を操作できないため、別権限として扱う。

### Cloud DNS

`dns.managedZones.get` がなく private zone の検出が Forbidden になった問題を修正した。

- `dns.managedZones.get`
- `dns.managedZones.list`

bootstrap 完了判定には、impersonated deployer が実際にこれらの読み取りを通過できることを使う。ロールが付いたように見えても IAM 反映前なら完了扱いにしない。

### IAM 反映待ち

- IAM 反映に見える失敗だけを自動再試行する
- 最大 2 分間の bounded retry とする
- 任意の 403、API 無効、組織ポリシー拒否まで「反映待ち」として隠さない
- Cloud DNS API 無効と IAM 不足を同じ成功扱いにしない
- 再試行後も失敗する場合は、具体的な権限名と API を画面に残す

### 404 の扱い

HAR で大量に見えた 404 の一部は、preflight が「まだ作られていない候補リソース」を GET しているために発生する。現在は API ごとに 404 の意味を分けた。

- 作成前の候補リソースの 404 は `absent` として計画へ渡す
- 親リソースや所有権証跡の 404 は安全上の失敗として扱う
- 403、500、不正 JSON を 404 と同じ「未作成」へ丸めない
- 空本文として認めるのは HTTP 204 だけにした
- 不正 JSON、配列、primitive、`null` を有効な Google API payload として採用しない

### Chrome Policy API

`policies:resolve` が `Internal error encountered` を返したケースでは、Google 側の 500 を「ポリシーなし」や「権限不足」と推測しないようにした。

- `chrome-policy` と `chrome-group-policy` を別の検出項目として表示する
- Google のエラー本文をサニタイズして診断に残す
- 500 のままなら Apply を fail-closed にする
- API の一時障害を権限付与で直ったことにしない

外部 API が 500 を返し続ける場合、拡張機能だけで成功へ変えることはできない。再試行しても同じなら Google Workspace 側の API 状態を確認する必要がある。

## preflight、承認、Apply

### 信頼済み事前確認

「信頼済み事前確認を実行」が押せない場合に、足りない条件を画面へ出すようにした。

- Cloud と Workspace の接続検証
- VPC、リージョン、アーキテクチャ固有項目
- immutable source image
- private hostname と backend URL
- Access Level、OU、group
- 既存バックエンドの接続確認
- 選択したパスに必要な API と権限

不足項目を一つの generic error に隠さず、構成エラーと Google API エラーを分けて表示する。

### プランと承認

- プランを構成ハッシュへ固定する
- 承認をプランハッシュと操作者へ固定する
- 承認は短時間、1 回限りとする
- 構成変更、OS 選択変更、private hostname 変更で承認を無効化する
- JSON のキー順が違うだけの同一 Option B 構成は同じ意味として扱う
- サーバー／拡張機能が正規化した hostname や principal は、同じ値として比較する
- 古いプランに `created_at` や `expires_at` がない場合でも、承認済みの正確な構成なら互換処理で続行できる
- ブラウザから渡された actor 名を監査主体として信用しない

### 「適用へ進む」ボタン

チェックボックスと「適用へ進む」が灰色のままになる問題を修正した。

- restored plan と現在の構成を canonical hash で比較する
- 同じ内容なら、オブジェクトのキー順や保存時の正規化差で無効化しない
- approval が別構成、期限切れ、使用済み、別操作者なら無効のままにする
- preflight に read-only の検出エラーが残る場合は Apply を有効化しない
- interrupted Run がある場合、新しいプランを作らず、その Run の再開へ誘導する
- rollback が終端している場合、古い進捗を実行中として残さない

### Apply の進行表示

`32件中2件、6%` のまま終わったか判断できなかった問題を修正した。

- pending、running、succeeded、failed、rolling_back、rolled_back、rollback_failed、rollback_unavailable、interrupted を別表示にした
- `rolling_back` は進行中として扱う
- `rolled_back` は完了として扱う
- 成功、失敗、ロールバック完了、手動確認待ちの終端文を表示する
- 現在の操作と、記録済み操作数だけで完了と推測しない
- ページ再読み込み後も同じ Run を取得して表示する

## 再開とロールバック

### 再開ボタン

Step 6 に説明だけあって実物がなかった再開／ロールバック再試行ボタンを、Run の状態に応じて表示するようにした。

- `interrupted` は同じ Run を再開する
- `rollback_failed` は補償可能性を再確認した後、同じロールバックを再試行する
- `rollback_unavailable` は現行スキーマで終端済みなら再試行を出さない
- `rolling_back` は新規 Apply を許可せず、その Run の進捗を追う
- ページ再読み込み後も latest teardown を取得し、再開できる

### 失敗全件の表示

以前の UI は `.reverse().find()` で最後の失敗 1 件しか表示していなかった。実際には同じロールバックで複数ステップが失敗しており、1 件ずつ直しているように見えていた。

現在は次をすべて同時に表示する。

- `rollback_failed` の全操作
- 各操作の `resource_key`
- 各操作の `error_code`
- 自動削除できない可能性がある残存リソース
- provider、resource type、resource name
- owned／shared の区別

これにより、`gateway-missing-delegating-account`、`iam-ownership-checkpoint-missing`、その他の失敗を 1 回の画面で確認できる。

### 補償プリフライト

ロールバックを始める前に、全ステップの before-image と所有権 checkpoint をネットワークアクセスなしで判定する `compensationCapability` を追加した。

- 1 件でも証跡が足りなければ Google API の変更リクエストを 0 件にする
- Run を `rollback_unavailable` へ終端する
- 同じ失敗を繰り返す再試行ボタンを消す
- 手動削除候補を表示する
- fail-closed の所有権ゲートは緩めない

これは `iam-ownership-checkpoint-missing` を握りつぶして削除を続ける修正ではない。証跡がない IAM を拡張機能が推測で戻すことはしない。

### before-image とライフサイクルスキーマ

- in-memory `Map` だけにあった before-image を IndexedDB の Run step に保存する
- MV3 service worker が停止しても、再開後に同じ before-image を使う
- approval、run、step に共通の lifecycle schema version を付ける
- 古い Run は再開時に 1 回だけ全項目を検証する
- 採用できる場合は現行スキーマへ引き上げる
- 採用できない場合は `rollback_unavailable` として封じる
- 実行中の各所へ legacy 特例を増やさない

### BeyondCorp Security Gateway

到達不能だった Gateway の安全削除経路を整理した。

- durable ownership marker が一致する場合だけ削除候補にする
- Gateway 配下の application inventory を全ページ確認する
- application が残っていれば Gateway を削除しない
- Gateway が既にない場合は削除済みとして扱う
- 所有権 checkpoint がなければ `generic-resource-ownership-checkpoint-missing` で停止する
