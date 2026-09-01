# Secure Gateway Studio 0.2.24 パッチノート — ランタイムと検証

Manifest V3 と Chrome API、ガイドと表示、エラーメッセージ、0.2.24 の検証結果。

累積パッチノート [`PATCH_NOTES_0.2.24_JA.md`](../../PATCH_NOTES_0.2.24_JA.md) の一部である。全体の索引、リリース概要、版別の経緯はそちらを参照すること。

---

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
