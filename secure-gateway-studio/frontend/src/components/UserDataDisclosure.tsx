import type { Locale } from "../lib/setup-state";

interface UserDataDisclosureProps {
  busy?: boolean;
  locale: Locale;
  onAccept: () => void;
}

const copy = {
  en: {
    eyebrow: "Before connecting to Google",
    title: "How this administrator tool handles data",
    intro:
      "To plan and perform the changes you approve, the extension handles the following data:",
    items: [
      "your administrator email, immutable Google account identifier, and short-lived Google OAuth authentication information. The identifier binds approvals and privileged actions to the same signed-in administrator;",
      "Workspace organizational units, groups, users in the selected pilot OU, tenant domain, Chrome policies, DLP rules, managed-profile signals, and licence status;",
      "Google Cloud project, IAM, network, DNS, certificate, Secret Manager, BeyondCorp, billing-status, and diagnostic status/method/request identifiers. Diagnostic reads exclude URL paths, query strings, IP addresses, principals, and free-form log payloads.",
      "when you approve Security Gateway creation, the extension enables full Secure Gateway connection records in Cloud Logging in the selected Google Cloud project. The records’ contents, retention, and access follow your Google Cloud configuration, and the developer receives none of them. The extension reads only its strict sanitized diagnostic fields, excluding URL paths, query strings, IP addresses, principals, and free-form log payloads.",
    ],
    storage:
      "Requests go only over HTTPS to the Google APIs needed for the feature you choose. Configuration, approvals, resumable checkpoints, and audit evidence are encrypted at rest in this Chrome profile with a non-extractable key. The unlimitedStorage permission protects only this safety ledger from automatic quota eviction; it does not collect browsing data or send additional data anywhere. OAuth access tokens stay in memory. When the extension generates a TLS private key, it is kept in session-only storage, sent only to your own Secret Manager, and cleared when the run terminates. If you select an existing public-certificate secret, its exact certificate and private-key version is read from your Secret Manager only to validate and configure that approved endpoint. That existing private key stays in memory during validation; the extension never persists it, saves it as a file, passes it to chrome.downloads, or retransmits it, and the approved VM later reads the pinned version directly from your Secret Manager.",
    limitedUse:
      "The developer receives no tenant data. There is no advertising, analytics, profiling, sale, or human review of your data. Data is used only to provide this extension’s disclosed deployment, verification, evidence, and cleanup features.",
    privacy: "Read the complete Privacy Policy",
    accept: "I understand and continue",
  },
  ja: {
    eyebrow: "Google に接続する前に",
    title: "この管理ツールが扱うデータ",
    intro:
      "承認された変更を計画・実行するため、拡張機能は次のデータを扱います。",
    items: [
      "管理者のメールアドレス、変更されない Google アカウント識別子、短時間だけ有効な Google OAuth 認証情報。アカウント識別子は、承認と権限を伴う操作を同じログイン中の管理者に結び付けるために使います",
      "Workspace の組織部門、グループ、選択したパイロット OU 内のユーザー、テナントドメイン、Chrome ポリシー、DLP ルール、管理対象プロファイルのシグナル、ライセンス状態",
      "Google Cloud のプロジェクト、IAM、ネットワーク、DNS、証明書、Secret Manager、BeyondCorp、課金状態、診断用のステータス・メソッド・リクエスト識別子。診断では URL パス、クエリ文字列、IP アドレス、プリンシパル、自由形式のログ本文を取得しません",
      "Security Gateway の作成を承認すると、拡張機能は選択した Google Cloud プロジェクトの Cloud Logging に Secure Gateway の完全な接続レコードを記録する機能を有効にします。レコードの内容、保持期間、アクセス管理はお客様の Google Cloud 設定に従い、開発者はこれらのレコードを一切受け取りません。拡張機能が読み取るのは厳格に制限・無害化した診断フィールドだけで、URL パス、クエリ文字列、IP アドレス、プリンシパル、自由形式のログ本文は取得しません",
    ],
    storage:
      "通信先は、選択した機能に必要な Google API に限られ、すべて HTTPS です。設定、承認、再開用チェックポイント、監査証跡は、抽出できない鍵で暗号化してこの Chrome プロファイル内に保存します。unlimitedStorage 権限は、この安全台帳が容量制限で自動削除されることを防ぐためだけに使い、閲覧データの収集や追加の外部送信には使いません。OAuth アクセストークンはメモリだけに保持します。拡張機能が TLS 秘密鍵を生成する場合はセッション限定領域に保持し、お客様自身の Secret Manager だけに送信して、実行終了時に消去します。既存の公開証明書シークレットを選んだ場合は、承認したエンドポイントの検証と構成のためだけに、お客様の Secret Manager から証明書と秘密鍵の特定バージョンを読み取ります。この既存秘密鍵は検証中のメモリだけに保持し、拡張機能が永続化したり、ファイルとして保存したり、chrome.downloads に渡したり、再送信したりすることはありません。承認済み VM は、固定された同じバージョンを後からお客様の Secret Manager から直接読み取ります。",
    limitedUse:
      "開発者はテナントデータを受け取りません。広告、解析、プロファイリング、販売、人による閲覧は行いません。データは、明示されたデプロイ、検証、証跡、クリーンアップ機能の提供にだけ使用します。",
    privacy: "プライバシーポリシー全文を読む",
    accept: "内容を理解して続行",
  },
} as const;

export function UserDataDisclosure({ busy = false, locale, onAccept }: UserDataDisclosureProps) {
  const message = copy[locale];
  return (
    <main className="data-disclosure-page">
      <section aria-labelledby="data-disclosure-title" className="data-disclosure-card">
        <p className="data-disclosure-eyebrow">{message.eyebrow}</p>
        <h1 id="data-disclosure-title">{message.title}</h1>
        <p>{message.intro}</p>
        <ul>
          {message.items.map((item) => <li key={item}>{item}</li>)}
        </ul>
        <p>{message.storage}</p>
        <p className="data-disclosure-limited-use">{message.limitedUse}</p>
        <div className="data-disclosure-actions">
          <a href="https://test-domain.dev/privacy.html" rel="noreferrer" target="_blank">
            {message.privacy}
          </a>
          <button className="primary-action" disabled={busy} onClick={onAccept} type="button">
            {message.accept}
          </button>
        </div>
      </section>
    </main>
  );
}
