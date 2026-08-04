import type { Messages } from "../../i18n/messages";
import type { ChromePlatform, SetupState } from "../../lib/setup-state";
import { CheckIcon, InfoIcon } from "../../components/Icons";

interface PlatformSelectorProps {
  messages: Messages;
  platforms: SetupState["platforms"];
  onToggle: (platform: ChromePlatform) => void;
}

const platformLabels: Record<ChromePlatform, string> = {
  macos: "macOS",
  windows: "Windows",
  linux: "Linux",
  chromeos: "ChromeOS",
};

const platformSymbols: Record<ChromePlatform, string> = {
  macos: "●",
  windows: "⊞",
  linux: "♙",
  chromeos: "◉",
};

export function PlatformSelector({
  messages,
  platforms,
  onToggle,
}: PlatformSelectorProps) {
  return (
    <section className="form-section platform-section">
      <h2>
        {messages.platformsTitle}
        <em>({messages.managedChromeOnly})</em>
      </h2>
      <div className="platform-grid">
        {(Object.keys(platformLabels) as ChromePlatform[]).map((platform) => (
          <label className="platform-option" key={platform}>
            <input
              checked={platforms[platform]}
              onChange={() => onToggle(platform)}
              type="checkbox"
            />
            <span className="checkbox-visual">
              {platforms[platform] ? <CheckIcon size={15} /> : null}
            </span>
            <span aria-hidden="true" className={`platform-symbol ${platform}`}>
              {platformSymbols[platform]}
            </span>
            <span>{platformLabels[platform]}</span>
          </label>
        ))}
      </div>
      <p className="information-line">
        <InfoIcon size={19} />
        <span>{messages.platformNote}</span>
      </p>
    </section>
  );
}
