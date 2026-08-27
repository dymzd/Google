import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runtimeCapabilities as extensionCapabilities } from "../src/ui/transport.ts";
import { runtimeCapabilities as localCapabilities } from "../../frontend/src/lib/transport.ts";
import {
  constrainSetupStateToRuntime,
  defaultSetupState,
} from "../../frontend/src/lib/setup-state.ts";

assert.equal(extensionCapabilities.cepDeployer, true);
assert.equal(extensionCapabilities.internalHttpsLbArchitecture, true);
assert.equal(extensionCapabilities.sessionSignIn, true);
assert.equal(extensionCapabilities.sessionSignOut, true);
assert.equal(extensionCapabilities.recommendedPocSourceImage, true);
assert.equal(extensionCapabilities.userDataDisclosure, true);
assert.equal(extensionCapabilities.vpcNetworkCatalog, true);
assert.equal(localCapabilities.cepDeployer, false);
assert.equal(localCapabilities.internalHttpsLbArchitecture, true);
assert.equal(localCapabilities.sessionSignIn, false);
assert.equal(localCapabilities.sessionSignOut, false);
assert.equal(localCapabilities.recommendedPocSourceImage, false);
assert.equal(localCapabilities.userDataDisclosure, false);
assert.equal(localCapabilities.vpcNetworkCatalog, false);
assert.equal(
  constrainSetupStateToRuntime(
    { ...defaultSetupState, mode: "production" },
    localCapabilities.internalHttpsLbArchitecture,
  ).backendKind,
  "managed_sample",
);

const disclosureSource = await readFile(
  fileURLToPath(new URL("../../frontend/src/components/UserDataDisclosure.tsx", import.meta.url)),
  "utf8",
);
assert.match(disclosureSource, /administrator email, immutable Google account identifier/);
assert.match(disclosureSource, /binds approvals and privileged actions/);
assert.match(disclosureSource, /developer receives no tenant data/i);
assert.match(disclosureSource, /encrypted at rest.*non-extractable key/i);
assert.match(
  disclosureSource,
  /existing public-certificate secret[\s\S]*?private key[\s\S]*?never persists it, saves it as a file, passes it to chrome\.downloads, or retransmits it/i,
);
assert.match(disclosureSource, /test-domain\.dev\/privacy\.html/);
assert.match(
  disclosureSource,
  /approve Security Gateway creation[\s\S]*?enables full Secure Gateway connection records in Cloud Logging[\s\S]*?contents, retention, and access follow your Google Cloud configuration[\s\S]*?developer receives none of them[\s\S]*?excluding URL paths, query strings, IP addresses, principals, and free-form log payloads/i,
);
assert.match(
  disclosureSource,
  /Security Gateway の作成を承認すると[\s\S]*?Cloud Logging[\s\S]*?完全な接続レコード[\s\S]*?内容、保持期間、アクセス管理はお客様の Google Cloud 設定に従い[\s\S]*?開発者はこれらのレコードを一切受け取りません/,
);

const setupSource = await readFile(
  fileURLToPath(
    new URL("../../frontend/src/features/setup/ConfigurationSteps.tsx", import.meta.url),
  ),
  "utf8",
);
assert.match(
  setupSource,
  /runtimeCapabilities\.internalHttpsLbArchitecture && state\.mode === "poc" \? \([\s\S]*?title={copy\.internalHttpsLb}[\s\S]*?\) : null/,
);
assert.match(setupSource, /copy\.configureSampleVm/);
assert.match(setupSource, /runtimeCapabilities\.vpcNetworkCatalog/);
assert.match(setupSource, /listVpcNetworkOptions\(state\.projectId\)/);
assert.match(setupSource, /runtimeCapabilities\.recommendedPocSourceImage/);
assert.match(setupSource, /copy\.sourceImageAutoHint/);
assert.match(setupSource, /getRecommendedPocSourceImage\(state\.projectId\)/);
assert.match(setupSource, /setSampleImageResolved\(option\.value\)/);
assert.match(setupSource, /copy\.sampleImageResolveFailed/);
assert.match(setupSource, /service-account-pinned-identity-missing/);
assert.match(setupSource, /copy\.bootstrapDeletedDeployerConfirm/);
assert.match(setupSource, /onBootstrapCloud\(false, false, true\)/);

const appSource = await readFile(
  fileURLToPath(new URL("../../frontend/src/App.tsx", import.meta.url)),
  "utf8",
);
assert.match(appSource, /runtimeCapabilities\.recommendedPocSourceImage/);
assert.match(appSource, /getRecommendedPocSourceImage\(setup\.projectId\)/);
assert.match(appSource, /setupForPlan = \{ \.\.\.setup, sourceImage: recommendedImage\.value \}/);
assert.match(appSource, /findRecoverableDeploymentRun\(await listDeploymentRuns\(\)\)/);
assert.match(
  appSource,
  /RECOVERABLE_RUN_STATUSES[\s\S]{0,260}?"failed"[\s\S]{0,260}?"rollback_unavailable"/,
);
assert.match(
  appSource,
  /recoverableRun !== null[\s\S]{0,300}?setRun\(recoverableRun\)[\s\S]{0,300}?currentStep: 6/,
);
assert.match(
  setupSource,
  /const retryAvailable =[\s\S]{0,400}?"rollback_failed"/,
);
assert.match(setupSource, /\{run && retryAvailable && \([\s\S]{0,500}?copy\.retryRollback/);
assert.match(setupSource, /failedOperations\.map[\s\S]{0,400}?operation\.error_code/);
assert.match(setupSource, /manualCleanupTitle[\s\S]{0,500}?residualResources\.map/);
assert.match(appSource, /principal\.value\.trim\(\)\.toLowerCase\(\)/);
assert.match(
  appSource,
  /private_hostname: specification\.private_hostname\.trim\(\)\.toLowerCase\(\)\.replace/,
);
assert.match(setupSource, /cost={messages\.guide\.architectures\[0\]\.estimatedCost}/);
assert.match(setupSource, /cost={messages\.guide\.architectures\[1\]\.estimatedCost}/);
assert.match(setupSource, /cost={messages\.guide\.architectures\[2\]\.estimatedCost}/);
assert.doesNotMatch(setupSource, /disabled={!runtimeCapabilities\.internalHttpsLbArchitecture}/);
assert.match(setupSource, /label={copy\.upstreamVpcProjectId}/);
assert.doesNotMatch(setupSource, /10\.10\.0\.2|secgw-nat-static-ip|default \/ RUNNING/);
assert.match(
  setupSource,
  /const networkProjectId =[\s\S]{0,220}?state\.upstreamVpcProjectId\.trim\(\)/,
);

const messagesSource = await readFile(
  fileURLToPath(new URL("../../frontend/src/i18n/messages.ts", import.meta.url)),
  "utf8",
);
assert.doesNotMatch(messagesSource, /available only in the separate local loopback app/);
assert.doesNotMatch(messagesSource, /Chrome 拡張機能ではこのパスを非表示にし、要求されても拒否します/);
assert.match(messagesSource, /Create a private sample VM during approved Apply/);
assert.match(messagesSource, /Option A requires an existing private HTTPS application/);
assert.match(messagesSource, /管理対象サンプルでは、Option CのNginx層とプライベートHTTPバックエンドVM/);
assert.match(messagesSource, /月額概算[^\n]*USD/);
assert.match(messagesSource, /Before final Apply, it changes only the deployer service account/);
assert.match(messagesSource, /初回準備で明示的に確認したデプロイヤーSA/);
assert.match(messagesSource, /10\.42\.0\.0\/24 subnet[\s\S]*?blocks overlaps or resource collisions/);
assert.doesNotMatch(messagesSource, /10\.0\.0\.0\/16 VPC with zero conflicts/);
assert.match(messagesSource, /Google Cloud mutations after bootstrap use the pinned keyless deployer/);
assert.match(messagesSource, /初回準備後のGoogle Cloud変更は、固定したキーレスデプロイヤーSA/);
assert.match(messagesSource, /Apply only persists the matrix/);
assert.match(messagesSource, /Applyはマトリクスの保存だけ/);
assert.match(messagesSource, /evaluate all safety gates/);
assert.match(messagesSource, /すべての安全ゲート/);
assert.match(messagesSource, /approved run-scoped backend hostname and reserved private address/);
assert.match(messagesSource, /承認済みrunに記録されたバックエンドのホスト名と予約済みプライベートアドレス/);
assert.match(messagesSource, /Chrome > Connectors > Chrome Root Store/);
assert.match(messagesSource, /Chrome］>［コネクタ］>［Chrome Root Store/);
assert.match(messagesSource, /tamper-evident cryptographic audit trail/);
assert.match(
  messagesSource,
  /method: "POST",[\s\S]{0,180}?projects\/\{projectId\}\/roles"[\s\S]{0,300}?roleId is supplied in the request body/,
);
assert.match(
  messagesSource,
  /method: "PATCH",[\s\S]{0,180}?projects\/\{projectId\}\/roles\/\{roleId\}"[\s\S]{0,300}?Updates the existing compatibility-named custom role/,
);
assert.match(messagesSource, /configured for the created subnet in the VPC selected in this run/);
assert.match(messagesSource, /作成済みサブネットにCloud RouterとCloud NATが構成/);
assert.doesNotMatch(messagesSource, /20 safety gates|20個の安全ゲート/);
assert.doesNotMatch(messagesSource, /All mutations use keyless service-account impersonation/);
assert.doesNotMatch(messagesSource, /10\.10\.0\.2/);
assert.doesNotMatch(messagesSource, /tamper-proof cryptographic/);
assert.doesNotMatch(messagesSource, /Run acceptance suite T01[–-]T09/);
assert.doesNotMatch(messagesSource, /Egress Fixed IP|固定送信元IP|intended egress IP|意図した送信元 IP/);
assert.doesNotMatch(messagesSource, /Creates or updates the compatibility-named custom role/);
assert.match(messagesSource, /PoC mode does not prove that selected existing resources are non-production/);
assert.match(messagesSource, /PoCモードだけでは、選択した既存リソースが非本番であることを保証しません/);
assert.doesNotMatch(messagesSource, /without mutating production|prevent accidental production impact/);
assert.match(messagesSource, /current value safely matches that run's recorded managed-after state/);
assert.match(messagesSource, /記録済みmanaged-after状態と安全に一致する場合だけ復元/);
assert.match(messagesSource, /sending write with an unknown result or later drift is retained/);
assert.doesNotMatch(messagesSource, /secgw-nat-static-ip|10\.10\.0\.2/);
assert.match(messagesSource, /dedicated-VPC path with private VMs creates Cloud NAT/);
assert.match(messagesSource, /existing VPC must provide verified private egress/);
assert.match(messagesSource, /internal-HTTPS-LB path has no Nginx tier but does create its private sample-backend VM/);
assert.match(messagesSource, /プライベートVMを持つ専用VPC方式はCloud NATを作成/);
assert.doesNotMatch(messagesSource, /internal HTTPS load balancer need no package egress|内部HTTPS LBはパッケージ送信経路を必要としません/);
assert.doesNotMatch(
  messagesSource,
  /"private-egress": "Apply creates Cloud NAT for controlled package egress/,
);
assert.match(
  messagesSource,
  /at most 10 unique users[\s\S]{0,500}?within 4 Directory pages[\s\S]{0,500}?5-second deadline/,
);
assert.match(
  messagesSource,
  /最大10名[\s\S]{0,500}?4ページ以内[\s\S]{0,500}?5秒/,
);
assert.match(
  messagesSource,
  /project IAM and Access Policy IAM contain no residual binding[\s\S]{0,300}?retire the old numeric identity/,
);
assert.match(messagesSource, /safely restore the soft-deleted role/);
assert.match(messagesSource, /旧数値IDを恒久的に廃止/);

const cepPageSource = await readFile(
  fileURLToPath(
    new URL("../../frontend/src/features/cep/CepDeployerPage.tsx", import.meta.url),
  ),
  "utf8",
);
assert.match(cepPageSource, /useState<boolean>\(false\)/);
assert.doesNotMatch(
  cepPageSource,
  /const \[autoSubOus,[^\n]+useState<boolean>\(true\)/,
);
assert.match(cepPageSource, /className="cep-inline-note">\{m\.licensePilotLimitNotice\}/);

const routerSource = await readFile(
  fileURLToPath(new URL("../src/background/router.ts", import.meta.url)),
  "utf8",
);
assert.doesNotMatch(routerSource, /extension-internal-https-lb-unsupported/);
assert.match(routerSource, /deleted_deployer_rebootstrap_confirmation/);
assert.match(routerSource, /RECREATE_DELETED_DEPLOYER/);

const serviceWorkerSource = await readFile(
  fileURLToPath(new URL("../src/background/service-worker.ts", import.meta.url)),
  "utf8",
);
assert.match(serviceWorkerSource, /retiredBootstrapOwnershipPins/);
assert.match(serviceWorkerSource, /provider-confirmed-deleted/);
assert.match(serviceWorkerSource, /active-run-deployer-retirement-blocked/);

const frontendSourceDirectory = fileURLToPath(new URL("../../frontend/src/", import.meta.url));
async function sourceFiles(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await sourceFiles(path));
    else if (/\.tsx?$/.test(entry.name)) files.push(path);
  }
  return files;
}

const inlineStyleFiles: string[] = [];
for (const path of await sourceFiles(frontendSourceDirectory)) {
  if (/\bstyle\s*=\s*\{/.test(await readFile(path, "utf8"))) inlineStyleFiles.push(path);
}
assert.deepEqual(
  inlineStyleFiles,
  [],
  "The shared UI must not use React inline styles because the extension CSP blocks style-src-attr",
);

const manifest = JSON.parse(
  await readFile(fileURLToPath(new URL("../manifest.json", import.meta.url)), "utf8"),
) as { content_security_policy?: { extension_pages?: string } };
const extensionCsp = manifest.content_security_policy?.extension_pages ?? "";
assert.match(extensionCsp, /(?:^|;)\s*style-src 'self'(?:;|$)/);
assert.doesNotMatch(extensionCsp, /style-src[^;]*'unsafe-inline'/);

// Interactive Google consent has exactly one implementation and it is silent
// unless a person asks for it. That makes every link in the chain from a click
// to chrome.identity load-bearing: 0.2.24 dropped the client method alone and
// left a handler nothing could call, so a Chrome profile that had never
// consented could not be recovered from inside the product. Assert the whole
// path, not just its ends.
{
  const read = async (path: string) =>
    await readFile(fileURLToPath(new URL(path, import.meta.url)), "utf8");
  const api = await read("../../frontend/src/lib/api.ts");
  const router = await read("../src/background/router.ts");
  const worker = await read("../src/background/service-worker.ts");
  const cep = await read("../../frontend/src/features/cep/CepDeployerPage.tsx");

  assert.match(api, /export async function signInSession\(/);
  assert.match(api, /runtimeCapabilities\.sessionSignIn/);
  assert.match(api, /"\/api\/v1\/auth\/sign-in"/);
  assert.match(router, /"POST \/api\/v1\/auth\/sign-in"/);
  assert.match(router, /await context\.signIn\(\)/);
  assert.match(worker, /signIn: establishAdministratorSession/);
  // The wizard is where a new operator lands; the CEP button promises the
  // same thing in its label.
  assert.match(setupSource, /signInSession\(\)/);
  assert.match(setupSource, /onClick=\{\(\) => void handleSignIn\(\)\}/);
  assert.match(cep, /signInSession\(\)/);
}

console.log("UI capability, CSP, guide-boundary, and user-data disclosure checks passed");
