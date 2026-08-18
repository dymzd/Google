import type { Messages } from "../../i18n/messages";
import type {
  CepDlpAction,
  CepDlpMatrixRuleConfig,
  CepDlpMatrixState,
  CepDlpRuleId,
} from "../../lib/api";

interface DlpMatrixTableProps {
  messages: Messages;
  matrix: CepDlpMatrixState;
  onChange: (matrix: CepDlpMatrixState) => void;
  region: string;
  onRegionChange: (region: string) => void;
}

const DLP_REGIONS: Array<{ value: string; label: string }> = [
  { value: "JP", label: "Japan (マイナンバー・銀行口座)" },
  { value: "US", label: "United States (SSN / Driver's License)" },
  { value: "GB", label: "United Kingdom (National Insurance)" },
  { value: "DE", label: "Germany (Identity Card)" },
  { value: "FR", label: "France (NIR)" },
  { value: "CA", label: "Canada (SIN)" },
  { value: "AU", label: "Australia (TFN)" },
  { value: "KR", label: "South Korea (RRN)" },
  { value: "SG", label: "Singapore (NRIC)" },
  { value: "IN", label: "India (Aadhaar)" },
];

const ACTION_CYCLE: CepDlpAction[] = ["auditOnly", "warnUser", "blockContent", "off"];

export const DEFAULT_DLP_MATRIX: CepDlpMatrixState = {
  universal_upload: { upload: "auditOnly", byodOnly: false },
  universal_download: { download: "auditOnly", byodOnly: false },
  payment_card: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
  national_id: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
  access_level: { upload: "warnUser", download: "warnUser", paste: "warnUser", print: "warnUser", byodOnly: true },
  watermark: { watermark: true, byodOnly: false },
  genai_block: { paste: "blockContent", upload: "blockContent", byodOnly: false },
};

export function DlpMatrixTable({
  messages,
  matrix,
  onChange,
  region,
  onRegionChange,
}: DlpMatrixTableProps) {
  const m = messages.cepDeployer;

  const currentMatrix = { ...DEFAULT_DLP_MATRIX, ...matrix };

  function updateRule(id: CepDlpRuleId, updater: (prev: CepDlpMatrixRuleConfig) => CepDlpMatrixRuleConfig) {
    const existing = currentMatrix[id] ?? {};
    const updated = updater(existing);
    onChange({ ...currentMatrix, [id]: updated });
  }

  function cycleAction(id: CepDlpRuleId, op: "upload" | "download" | "paste" | "print") {
    updateRule(id, (prev) => {
      const current = prev[op] ?? "off";
      const nextIndex = (ACTION_CYCLE.indexOf(current) + 1) % ACTION_CYCLE.length;
      return { ...prev, [op]: ACTION_CYCLE[nextIndex] };
    });
  }

  function toggleWatermark(id: CepDlpRuleId) {
    updateRule(id, (prev) => ({ ...prev, watermark: !prev.watermark }));
  }

  function toggleByodOnly(id: CepDlpRuleId) {
    updateRule(id, (prev) => ({ ...prev, byodOnly: !prev.byodOnly }));
  }

  function applyPreset(presetName: "recommended" | "strict" | "genai" | "audit") {
    switch (presetName) {
      case "recommended":
        onChange({
          universal_upload: { upload: "auditOnly", byodOnly: false },
          universal_download: { download: "auditOnly", byodOnly: false },
          payment_card: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
          national_id: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
          access_level: { upload: "warnUser", download: "warnUser", paste: "warnUser", print: "warnUser", byodOnly: true },
          watermark: { watermark: true, byodOnly: false },
          genai_block: { paste: "blockContent", upload: "blockContent", byodOnly: false },
        });
        break;
      case "strict":
        onChange({
          universal_upload: { upload: "warnUser", byodOnly: false },
          universal_download: { download: "auditOnly", byodOnly: false },
          payment_card: { upload: "blockContent", paste: "blockContent", print: "blockContent", byodOnly: false },
          national_id: { upload: "blockContent", paste: "blockContent", print: "blockContent", byodOnly: false },
          access_level: { upload: "blockContent", download: "blockContent", paste: "blockContent", print: "blockContent", byodOnly: true },
          watermark: { watermark: true, byodOnly: false },
          genai_block: { paste: "blockContent", upload: "blockContent", byodOnly: false },
        });
        break;
      case "genai":
        onChange({
          universal_upload: { upload: "off", byodOnly: false },
          universal_download: { download: "off", byodOnly: false },
          payment_card: { upload: "auditOnly", paste: "auditOnly", print: "off", byodOnly: false },
          national_id: { upload: "auditOnly", paste: "auditOnly", print: "off", byodOnly: false },
          access_level: { upload: "auditOnly", download: "off", paste: "auditOnly", print: "off", byodOnly: true },
          watermark: { watermark: false, byodOnly: false },
          genai_block: { paste: "blockContent", upload: "blockContent", byodOnly: false },
        });
        break;
      case "audit":
        onChange({
          universal_upload: { upload: "auditOnly", byodOnly: false },
          universal_download: { download: "auditOnly", byodOnly: false },
          payment_card: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
          national_id: { upload: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: false },
          access_level: { upload: "auditOnly", download: "auditOnly", paste: "auditOnly", print: "auditOnly", byodOnly: true },
          watermark: { watermark: true, byodOnly: false },
          genai_block: { paste: "auditOnly", upload: "auditOnly", byodOnly: false },
        });
        break;
    }
  }

  function renderActionBadge(action: CepDlpAction | undefined, onClick: () => void, label: string) {
    const act = action ?? "off";
    const badgeClass =
      act === "blockContent"
        ? "dlp-badge dlp-badge-block"
        : act === "warnUser"
        ? "dlp-badge dlp-badge-warn"
        : act === "auditOnly"
        ? "dlp-badge dlp-badge-audit"
        : "dlp-badge dlp-badge-off";

    const text =
      act === "blockContent"
        ? m.dlpActionBadgeBlock
        : act === "warnUser"
        ? m.dlpActionBadgeWarn
        : act === "auditOnly"
        ? m.dlpActionBadgeAudit
        : m.dlpActionBadgeOff;

    return (
      <button
        aria-label={`${label}: ${text}`}
        className={badgeClass}
        onClick={onClick}
        title={`${label} (${text}) - クリックして変更`}
        type="button"
      >
        {text}
      </button>
    );
  }

  return (
    <div className="dlp-matrix-container">
      <div className="dlp-matrix-header">
        <div>
          <h3>{m.dlpMatrixTitle}</h3>
          <p className="dlp-matrix-desc">{m.dlpMatrixSubtitle}</p>
        </div>
        <div className="dlp-region-selector">
          <label htmlFor="cep-dlp-matrix-region">{m.dlpRegionTitle}:</label>
          <select
            id="cep-dlp-matrix-region"
            onChange={(e) => onRegionChange(e.target.value)}
            value={region}
          >
            {DLP_REGIONS.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="dlp-matrix-presets">
        <span className="dlp-presets-label">プリセット:</span>
        <button
          className="secondary-action dlp-preset-btn"
          onClick={() => applyPreset("recommended")}
          type="button"
        >
          {m.dlpPresetRecommended}
        </button>
        <button
          className="secondary-action dlp-preset-btn"
          onClick={() => applyPreset("strict")}
          type="button"
        >
          {m.dlpPresetStrictZeroTrust}
        </button>
        <button
          className="secondary-action dlp-preset-btn"
          onClick={() => applyPreset("genai")}
          type="button"
        >
          {m.dlpPresetGenAiSecure}
        </button>
        <button
          className="secondary-action dlp-preset-btn"
          onClick={() => applyPreset("audit")}
          type="button"
        >
          {m.dlpPresetAuditOnly}
        </button>
      </div>

      <div className="dlp-table-wrapper">
        <table className="dlp-matrix-table" aria-label={m.dlpMatrixTitle}>
          <thead>
            <tr>
              <th scope="col" className="col-threat">{m.dlpColThreat}</th>
              <th scope="col" className="col-op">{m.dlpColUpload}</th>
              <th scope="col" className="col-op">{m.dlpColDownload}</th>
              <th scope="col" className="col-op">{m.dlpColPaste}</th>
              <th scope="col" className="col-op">{m.dlpColPrint}</th>
              <th scope="col" className="col-op">{m.dlpColWatermark}</th>
              <th scope="col" className="col-scope">{m.dlpColDeviceScope}</th>
            </tr>
          </thead>
          <tbody>
            {/* 1. All File Uploads */}
            <tr>
              <th scope="row">
                <strong>📤 {m.dlpRowUniversalUpload}</strong>
                <small>{m.dlpRowUniversalUploadDesc}</small>
              </th>
              <td>
                {renderActionBadge(
                  currentMatrix.universal_upload?.upload,
                  () => cycleAction("universal_upload", "upload"),
                  `${m.dlpRowUniversalUpload} ${m.dlpColUpload}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.universal_upload?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("universal_upload")}
                  type="button"
                >
                  {currentMatrix.universal_upload?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>

            {/* 2. All File Downloads */}
            <tr>
              <th scope="row">
                <strong>📥 {m.dlpRowUniversalDownload}</strong>
                <small>{m.dlpRowUniversalDownloadDesc}</small>
              </th>
              <td className="cell-na">—</td>
              <td>
                {renderActionBadge(
                  currentMatrix.universal_download?.download,
                  () => cycleAction("universal_download", "download"),
                  `${m.dlpRowUniversalDownload} ${m.dlpColDownload}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.universal_download?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("universal_download")}
                  type="button"
                >
                  {currentMatrix.universal_download?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>

            {/* 3. Payment Card Data */}
            <tr>
              <th scope="row">
                <strong>💳 {m.dlpRowPaymentCard}</strong>
                <small>{m.dlpRowPaymentCardDesc}</small>
              </th>
              <td>
                {renderActionBadge(
                  currentMatrix.payment_card?.upload,
                  () => cycleAction("payment_card", "upload"),
                  `${m.dlpRowPaymentCard} ${m.dlpColUpload}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                {renderActionBadge(
                  currentMatrix.payment_card?.paste,
                  () => cycleAction("payment_card", "paste"),
                  `${m.dlpRowPaymentCard} ${m.dlpColPaste}`,
                )}
              </td>
              <td>
                {renderActionBadge(
                  currentMatrix.payment_card?.print,
                  () => cycleAction("payment_card", "print"),
                  `${m.dlpRowPaymentCard} ${m.dlpColPrint}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.payment_card?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("payment_card")}
                  type="button"
                >
                  {currentMatrix.payment_card?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>

            {/* 4. National ID / PII Data */}
            <tr>
              <th scope="row">
                <strong>🪪 {m.dlpRowNationalId}</strong>
                <small>{m.dlpRowNationalIdDesc}</small>
              </th>
              <td>
                {renderActionBadge(
                  currentMatrix.national_id?.upload,
                  () => cycleAction("national_id", "upload"),
                  `${m.dlpRowNationalId} ${m.dlpColUpload}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                {renderActionBadge(
                  currentMatrix.national_id?.paste,
                  () => cycleAction("national_id", "paste"),
                  `${m.dlpRowNationalId} ${m.dlpColPaste}`,
                )}
              </td>
              <td>
                {renderActionBadge(
                  currentMatrix.national_id?.print,
                  () => cycleAction("national_id", "print"),
                  `${m.dlpRowNationalId} ${m.dlpColPrint}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.national_id?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("national_id")}
                  type="button"
                >
                  {currentMatrix.national_id?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>

            {/* 5. Unmanaged / BYOD Devices */}
            <tr>
              <th scope="row">
                <strong>💻 {m.dlpRowAccessLevel}</strong>
                <small>{m.dlpRowAccessLevelDesc}</small>
              </th>
              <td>
                {renderActionBadge(
                  currentMatrix.access_level?.upload,
                  () => cycleAction("access_level", "upload"),
                  `${m.dlpRowAccessLevel} ${m.dlpColUpload}`,
                )}
              </td>
              <td>
                {renderActionBadge(
                  currentMatrix.access_level?.download,
                  () => cycleAction("access_level", "download"),
                  `${m.dlpRowAccessLevel} ${m.dlpColDownload}`,
                )}
              </td>
              <td>
                {renderActionBadge(
                  currentMatrix.access_level?.paste,
                  () => cycleAction("access_level", "paste"),
                  `${m.dlpRowAccessLevel} ${m.dlpColPaste}`,
                )}
              </td>
              <td>
                {renderActionBadge(
                  currentMatrix.access_level?.print,
                  () => cycleAction("access_level", "print"),
                  `${m.dlpRowAccessLevel} ${m.dlpColPrint}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                <span className="dlp-scope-pill byod fixed">{m.dlpScopeByodOnly}</span>
              </td>
            </tr>

            {/* 6. Internal Sites & Watermark */}
            <tr>
              <th scope="row">
                <strong>🔒 {m.dlpRowWatermark}</strong>
                <small>{m.dlpRowWatermarkDesc}</small>
              </th>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={currentMatrix.watermark?.watermark ? "dlp-badge dlp-badge-audit" : "dlp-badge dlp-badge-off"}
                  onClick={() => toggleWatermark("watermark")}
                  type="button"
                >
                  {currentMatrix.watermark?.watermark ? "有効" : "オフ"}
                </button>
              </td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.watermark?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("watermark")}
                  type="button"
                >
                  {currentMatrix.watermark?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>

            {/* 7. Unapproved GenAI Block */}
            <tr>
              <th scope="row">
                <strong>🤖 {m.dlpRowGenAiBlock}</strong>
                <small>{m.dlpRowGenAiBlockDesc}</small>
              </th>
              <td>
                {renderActionBadge(
                  currentMatrix.genai_block?.upload,
                  () => cycleAction("genai_block", "upload"),
                  `${m.dlpRowGenAiBlock} ${m.dlpColUpload}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td>
                {renderActionBadge(
                  currentMatrix.genai_block?.paste,
                  () => cycleAction("genai_block", "paste"),
                  `${m.dlpRowGenAiBlock} ${m.dlpColPaste}`,
                )}
              </td>
              <td className="cell-na">—</td>
              <td className="cell-na">—</td>
              <td>
                <button
                  className={`dlp-scope-pill ${currentMatrix.genai_block?.byodOnly ? "byod" : "all"}`}
                  onClick={() => toggleByodOnly("genai_block")}
                  type="button"
                >
                  {currentMatrix.genai_block?.byodOnly ? m.dlpScopeByodOnly : m.dlpScopeAll}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
