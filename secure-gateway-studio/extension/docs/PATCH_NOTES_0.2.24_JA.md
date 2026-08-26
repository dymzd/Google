# Secure Gateway Studio 0.2.24 累積パッチノート

更新日: 2026-08-26
対象: Chrome 拡張機能版 Secure Gateway Studio
収録範囲: 0.2.0 の公開後から 0.2.24 までに行った修正、調査、検証環境の後片付け

## この文書の範囲

この文書には、今回のやり取りで確認した不具合と、その後に入れた修正をまとめている。最終的なコード変更の対象は Chrome 拡張機能と、拡張機能に同梱する共有フロントエンドである。ローカル FastAPI 版の機能を拡張するための変更ではない。

作業ツリーには複数リリース分の未コミット変更が含まれている。このため、ソースと既存資料から版を特定できた変更は版番号を明記し、特定できないものは「0.2.24 までの累積変更」として記載した。推測で版を割り当ててはいない。

なお、古い `docs/TEST_MATRIX.md` には「拡張機能版は Option B を非表示にする」という説明が残っている。一方、0.2.24 の実装、ガイド、UI 回帰テストは Option B の計画と Apply に対応している。このパッチノートでは現行コードを正とする。古い説明は別途更新が必要である。

## リリース概要

0.2.24 では、Google Cloud 上のデプロイヤーを意図的に削除した後、拡張機能に旧サービスアカウントの固定情報だけが残って再構成できなくなる問題を修正した。

今回直したのは、ローカル固定情報を無条件に消す処理ではない。拡張機能は次の条件をすべて確認してから旧 ID を廃止する。

- 現在ログインしている Google アカウントが、旧デプロイヤーに固定された操作者と一致する
- 固定されていたサービスアカウントが Google Cloud 上に存在しない
- カスタムロールが存在しないか、Google の論理削除状態で Secure Gateway Studio の完全なロール定義と一致する
- プロジェクト IAM と Access Policy IAM に、旧メールアドレス、旧数値 ID、旧カスタムロールの残存バインディングがない
- Apply、ロールバック、Teardown、CEP 変更が実行中ではない
- 利用者が削除済みデプロイヤーの再作成を専用ダイアログで明示的に承認した

確認後、拡張機能は旧数値 ID を監査用 tombstone として保存し、新しい数値 ID を持つサービスアカウントを作る。Google Cloud は削除したカスタムロール ID を最大 44 日間予約するため、同じ ID の新規作成だけでは復旧できない。0.2.24 は削除済みロールの定義と etag を検証し、安全に undelete してから新しいデプロイヤーへ権限を付与する。

## 版別の経緯

| 版 | 経緯 |
|---|---|
| 0.2.0 | Chrome Web Store へ最初にアップロードした版。デプロイヤーの操作者欄に人間のアカウントではなくサービスアカウントのメールアドレスを保存する不具合と、後続移行に必要な不変数値 ID を十分に保持していない問題があった。 |
| 0.2.1 | OpenID の `sub` を使った人間の不変 ID 確認、初回データ利用開示、AES-256-GCM による永続状態の暗号化、0.2.0 の平文状態を同意後に移行する処理を追加した。 |
| 0.2.2～0.2.17 | Step 3、Google API 検出、Apply、再開処理などを継続修正した。現在の作業ツリーだけでは、各変更をこの範囲の個別バージョンへ正確に割り当てられないため、後段の累積変更にまとめた。 |
| 0.2.18～0.2.21 | 同じロールバック経路で出た例外を順番に修正した。後の調査で、実際には 1 回のロールバックで複数ステップが同時に失敗しており、UI が最後の 1 件しか表示していなかったことが判明した。 |
| 0.2.22 調査時 | ロールバック不具合の根本原因を、診断情報の切り捨て、補償不能状態の非終端化、永続レコードのスキーマ版不足、揮発性 before-image、層をまたぐテスト不足に整理した。 |
| 0.2.23 | ロールバック前の全件判定、`rollback_unavailable` 終端、失敗全件と残存リソースの表示、ライフサイクルスキーマ、古い Run の一度限りの採用判定、実 executor を含む回帰テストを実装した。 |
| 0.2.24 | Google Cloud 側を全削除した後に残るデプロイヤー固定情報を、同一操作者、残存 IAM ゼロ、削除済みロールの完全一致を条件に安全に廃止し、再作成できるようにした。 |

## 配布物とバージョン

- Chrome Web Store へアップロードする形式は ZIP に統一した。CRX は生成しない。
- 0.2.0 がアップロード済みだったため、`manifest.json`、`package.json`、`package-lock.json` を `0.2.24` へ更新した。
- 生成物名を `secure-gateway-studio-0.2.24.zip` とした。
- ZIP 内の `manifest.json` が `0.2.24` であることを展開せずに検査した。
- ZIP 内に Manifest V3 の service worker、共有 UI、CSP、アイコン、ライセンス、第三者通知が含まれることを確認した。
- 最終 ZIP は 2,213,999 bytes。
- SHA-256 は `d31dd3f93a3c2e91d0cd2da5a27ebb9c27a4a318fa92b96366e19845a4ca2f09`。

## Step 3 の構成画面

### Option A

Option A は、既存のプライベート HTTPS アプリへ Secure Gateway から直接接続する方式として分離した。

- Nginx、追加 VM、Cloud NAT、オフロード証明書を作らない
- 既存 VPC と既存 HTTPS エンドポイントを必須とする
- 新規インフラの PoC 月額概算は `USD 0` と表示する
- 既存アプリ、既存 DNS、データ転送、既存基盤の料金は別途発生すると明記する
- 存在しない VM や Cloud NAT のコンソールリンクを表示しない

Option A 自体はサンプル VM を作らない。HTTPS のテスト先がない場合に表示するボタンは、Option B のプライベートサンプル VM を使う構成へ切り替える。Option A の定義を崩して、HTTP サンプル VM を直接ぶら下げる動作にはしていない。

### Option B

消えていた Option B を Step 3 に戻し、Chrome 拡張機能から計画、承認、Apply できるようにした。

- Regional Internal Application Load Balancer で HTTPS を終端する
- ILB からプライベートサンプル VM の HTTP 80 番へ転送する
- Nginx オフロード層は作らない
- `REGIONAL_MANAGED_PROXY` 用の proxy-only subnet を作成する
- リージョン health check、backend service、URL map、target HTTPS proxy、forwarding rule を同じ Run の所有リソースとして扱う
- Option B のサンプル VMは外部 IP を持たない
- 専用 VPC では Router と Cloud NAT を作る
- 既存 VPC を選んだ場合は、既存のプライベート送信経路を検証する
- 月額概算を `USD 80～90` と表示する

概算は `asia-northeast1`、720 時間、軽いトラフィックを前提にしている。最低 3 台相当の ILB proxy、e2-small のサンプル VM、20 GB ディスク、Cloud DNS、専用 VPC 時の Cloud NAT を含む。Chrome Enterprise Premium／Secure Gateway の契約料金、税、ログ量、イメージ料金、為替差は含めていない。

### Option C

従来の Nginx 方式を Option C として、Legacy／詳細設定内に整理した。

- プライベート HTTP アプリを使う場合の Nginx HTTPS-to-HTTP オフロードを維持した
- Managed Sample を選ぶと、承認済み Apply でプライベート HTTP バックエンド VM と Nginx 層を作る
- Existing HTTP を選ぶと、管理者が用意した到達可能な HTTP バックエンドを使う
- Existing HTTP のテスト先がない場合、Managed Sample へ切り替えるボタンを表示する
- 月額概算を `USD 45～60` と表示する

料金には Compute Engine、ディスク、Cloud DNS、Cloud NAT、ネットワーク転送、NAT 処理、割り当て IP、DNS クエリを含む。実際の金額はリージョンと稼働時間で変わる。

### サンプル VM の操作

「承認済み Apply でプライベートサンプル VM を作成」を押しても何も起きないように見えた問題を修正した。

- ボタンを押した時点では Google Cloud を変更しない
- 選択したアーキテクチャと、Run が所有するサンプル VM の desired state を設定する
- 推奨の不変イメージを自動取得し、`sourceImage` へ即時反映する
- 実際の VM 作成は、正確なプランを承認した後の Apply で行う
- Apply 後は Run の所有リソースとして記録し、ロールバックと Teardown の対象にする
- 画像取得に失敗した場合は、ボタンが無反応になるのではなくエラーを表示する

### 不変のハードニング済み VM イメージ

`Managed VM paths require an immutable hardened source image` で先へ進めなかった問題を修正した。

- 推奨 PoC イメージを Google Cloud から取得する setup API を追加した
- サンプル VM の操作時に推奨イメージを自動入力する
- Production 向けのイメージ検証では、イメージの完全なリソース名と不変数値 ID を確認する
- 空欄のまま Apply ボタンだけが無効になる状態を避け、取得中、取得済み、取得失敗を画面に表示する

### VPC 選択

- デプロイ先プロジェクト内の VPC は Google Cloud から取得し、ドロップダウンで選べるようにした
- VPC 一覧の取得中、取得失敗、候補なしを区別した
- Shared VPC または別プロジェクトの upstream は、プロジェクト ID を明示入力する
- 別プロジェクトの VPC は自動 bootstrap の対象にしない
- upstream プロジェクト側では、管理者が 5 権限だけを含むカスタムロールを別途作成し、デプロイ先プロジェクトのデプロイヤーへ付与する前提をガイドへ追加した

別プロジェクト側で必要な権限は次のとおり。

- `compute.networks.get`
- `compute.networks.use`
- `resourcemanager.projects.get`
- `resourcemanager.projects.getIamPolicy`
- `resourcemanager.projects.setIamPolicy`

### GCP、AWS、Azure、オンプレミス

既存バックエンドの場所として GCP、AWS、Azure、オンプレミスを選べるようにした。ただし、拡張機能が Cloud VPN、Interconnect、AWS VPN、オンプレミス側 VPN を自動構成するわけではない。

- 既存のプライベート接続があることを明示確認するチェックを追加した
- 接続確認がない状態では preflight を通さない
- GCP 以外のバックエンドは、到達経路を拡張機能が推測しない
- オンプレミス接続は Cloud VPN などを別途構成する必要がある

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

## Manifest V3 と Chrome API

- Manifest V3 の service worker で動作する
- 最低 Chrome バージョンは 142
- OAuth は `openid`、userinfo email、Directory、Cloud Identity Policy、Cloud Platform、Chrome Management Policy／Profiles、Licensing を宣言する
- host permission は Access Context Manager、Admin SDK、BeyondCorp、Chrome Management、Chrome Policy、Billing、Cloud Identity、Resource Manager、Compute、DNS、IAM、IAM Credentials、Licensing、Logging、OpenID Connect、Private CA、Secret Manager、Service Usage に限定する
- CSP は `default-src 'none'` を基準にし、script と style の inline 実行を許可しない
- UI の React inline style を禁止し、拡張機能 CSP と一致させる
- OAuth consent を起動時に自動表示せず、利用者が接続／検証ボタンを押した場合だけ開始する
- installed update でも cold-start reconciliation を実行し、必要な alarm を復元する

## ガイドと表示

- 英語と日本語を画面全体で切り替えられる
- 7 Step の下部ナビゲーションガイドを追加した
- 各 Step に、何を入力するか、何を自動変更するか、どの Google API を呼ぶかを表示する
- Option A、B、C の構成図、用途、制約、USD 概算を表示する
- Google Cloud Console、Admin console、VPC、NAT、Compute、Security Gateway へのリンクを構成に応じて出し分ける
- Apply 後のログ、所有／共有リソース、証拠、Teardown を Operations 画面に集約した
- 390 px 幅の画面でも navigation と主要 action を操作できるようにした

## エラーメッセージの改善

今回の調査で実際に確認したメッセージと対応は次のとおり。

| メッセージ | 対応 |
|---|---|
| `No 0.2.0 deployer identity is stored locally for explicit migration.` | ローカルヒント必須を廃止し、予約名、不変 ID、鍵、ロール、IAM の完全監査へ置き換えた。 |
| `The legacy deployer has project bindings outside the exact 0.2.0 allowlist...` | 差異を隠して採用せず、全 allowlist を表示し、必要なら分離デプロイヤーを別確認で作る。 |
| `Managed VM paths require an immutable hardened source image` | 推奨 PoC イメージの取得と自動入力を追加した。 |
| `compute.regionHealthChecks.get permission...` | Regional Health Check の get/create/delete をカスタムロールへ追加した。 |
| `dns.managedZones.get... Forbidden` | Cloud DNS の get/list を追加し、impersonated deployer で readiness を確認する。 |
| `The impersonated deployer has not yet completed the Cloud DNS read check...` | IAM 反映に限定した bounded retry と、API／組織制約の別エラー表示を追加した。 |
| `chrome-policy... Internal error encountered` | Google の 500 をサニタイズして表示し、ポリシーなしへ誤変換せず fail-closed にした。 |
| `The signed-in Google account differs from the operator who approved this run.` | 人間の email／sub と deployer の email／unique ID を分離し、0.2.0 の誤った `approvedBy` を移行する。 |
| `gateway-missing-delegating-account` | Gateway 作成後の delegating account を bounded polling し、Run と操作者の binding を durable にした。 |
| `rollback: iam-ownership-checkpoint-missing` | 証跡を推測せず、ロールバック前の全件判定で `rollback_unavailable` へ終端する。 |
| `手動削除が必要です` | 失敗全件と残存リソースを表示し、無限再試行を止めた。 |
| `The pinned deployer service account no longer exists...` | 0.2.24 の削除専用再作成フローを追加した。 |

## 検証

0.2.24 の最終コードで、次の検証をすべて実行した。

### 拡張機能

- TypeScript typecheck: 成功
- UI が呼ぶ 41 endpoint と service worker route の照合: 成功
- UI capability、CSP、ガイド境界、利用開示: 成功
- cold-start: 26 checks
- Google JSON transport: 5 checks
- canonical parity: 27 cases
- deployment spec round-trip／hash: 10 specs
- authentication: 58 checks
- storage safety: 24 checks
- encrypted v3 migration: 成功
- IndexedDB lifecycle: 42 checks
- audit chain: 21 checks
- planner parity: 10 plans
- executor parity: 6 scenarios、192 requests
- Option A request／readiness: 16 checks
- execution safety: 142 checks
- discovery parity: 4 scenarios、80 requests
- catalog: 46 checks
- crash／resume: 44 checks
- certificate／CSR: 47 checks
- acceptance: 23 checks
- evidence: 12 checks
- IAM policy safety: 23 checks
- teardown safety: 成功
- observability minimization: 成功
- CEP deployer: 178 checks

### フロントエンド

- Vitest: 8 test files、85 tests、全件成功
- Production build: 成功
- 生成 JavaScript: 約 498.73 kB、gzip 約 149.84 kB
- 生成 CSS: 約 70.97 kB、gzip 約 14.34 kB

追加した主な回帰ケースは次のとおり。

- 0.2.0 デプロイヤー移行の 2 回目確認
- 削除済みデプロイヤー再作成の専用確認
- soft-deleted custom role の etag 付き復元
- SA 作成後の worker crash
- project IAM だけ付与済みの途中状態からの再開
- 旧数値 ID の IAM binding が途中で差し込まれた場合の停止
- Option B の canonical plan 比較
- immutable PoC image の即時入力
- Apply の live progress と全 rollback error の同時表示
- `rollback_unavailable` 後に再試行を出さないこと
- rolling back／rolled back の表示

### レビューゲート

認証、IAM、データ削除、リリースを含むため `codex-review` を実行した。サブエージェントを使わない main-agent fallback で、architecture、diff、cross-check の 3 観点を確認した。

初回レビューでは、削除済みカスタムロール ID を単純再作成すると Google の最大 44 日間の予約に阻まれる P1 を検出した。etag 付き undelete と、途中停止用の durable recovery marker を追加して再レビューした。最終結果は `ok=true`、未確認範囲と未解決 blocking issue は 0 件。

## 更新手順

1. Chrome Web Store へ `secure-gateway-studio-0.2.24.zip` をアップロードするか、検証時は展開済み `dist/` を読み込む。
2. 拡張機能を再読み込みする。
3. 同じ Google 管理者アカウントで接続し直す。
4. Step 3 でデプロイヤーの自動準備を押す。
5. 通常 bootstrap の確認に同意する。
6. 削除済みデプロイヤー専用の確認が出た場合、表示された監査内容を読んで同意する。
7. bootstrap 後の Cloud 検証が成功するまで待つ。
8. 以前の Run のリソースを全削除した場合、その Run は再開せず、新しい preflight とプランを作る。
9. 新しいプランの構成、費用、作成リソースを確認し、承認後に Apply する。

## 既知の制約

- 現在は controlled staging／PoC 向け。Production 選択は画面に残すが無効化している。
- コードと offline verify が成功しても、実テナントの Chrome 管理、Access Level、証明書配布、T07／T09 を自動証明したことにはならない。
- Option A は既存 HTTPS アプリが必要。サンプル VM が必要なら Option B を使う。
- Option B の USD 80～90、Option C の USD 45～60 は見積書ではない。リージョン、稼働時間、トラフィック、契約で変わる。
- Chrome Policy API が Google 側で 500 を返し続ける場合は Apply できない。
- 証跡のない古い Run は、自動ロールバックできない。`rollback_unavailable` と手動削除一覧が正しい終端である。
- 削除済みロールの完全な定義が現在の SGS 定義と違う場合、0.2.24 は undelete しない。
- IAM に旧 ID または旧ロールの残存バインディングが 1 件でもあれば、デプロイヤー再作成は変更前に停止する。
- Shared VPC と他クラウド／オンプレミスの接続は、別プロジェクトまたは外部ネットワーク側の管理者作業が必要。

## HAR と認証情報

調査に使った HAR には OAuth access token が含まれる場合がある。HAR をリポジトリへ追加したり、公開 Issue へ添付したりしないこと。調査が終わった HAR は削除し、必要に応じて Google アカウントを再認証する。

このパッチノートでは、検証に使ったプロジェクト ID、Workspace customer ID、管理者メールアドレスを公開用の文書へ転載していない。
