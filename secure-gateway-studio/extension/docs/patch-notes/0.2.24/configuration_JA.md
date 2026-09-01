# Secure Gateway Studio 0.2.24 パッチノート — Step 3 の構成画面

Option A/B/C、サンプル VM、ハードニング済みイメージ、VPC 選択、対応プラットフォーム。

累積パッチノート [`PATCH_NOTES_0.2.24_JA.md`](../../PATCH_NOTES_0.2.24_JA.md) の一部である。全体の索引、リリース概要、版別の経緯はそちらを参照すること。

---

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
