import type { Messages } from "../../i18n/messages";
import type {
  CertificateStrategy,
  ChromePlatform,
  DeploymentMode,
  NetworkStrategy,
  SetupState,
} from "../../lib/setup-state";
import {
  GlobeIcon,
  InfoIcon,
  LockIcon,
  NetworkIcon,
  ShieldIcon,
} from "../../components/Icons";
import { ChoiceCard } from "./ChoiceCard";
import { PlatformSelector } from "./PlatformSelector";

interface ModeStepProps {
  messages: Messages;
  state: SetupState;
  onModeChange: (mode: DeploymentMode) => void;
  onPlatformToggle: (platform: ChromePlatform) => void;
  onNetworkChange: (strategy: NetworkStrategy) => void;
  onCertificateChange: (strategy: CertificateStrategy) => void;
}

export function ModeStep({
  messages,
  state,
  onModeChange,
  onPlatformToggle,
  onNetworkChange,
  onCertificateChange,
}: ModeStepProps) {
  const localPocDisabled = state.mode === "production";

  return (
    <>
      <section className="form-section">
        <h2>{messages.modeTitle}</h2>
        <div className="mode-grid">
          <ChoiceCard
            description={messages.pocDescription}
            icon={<InfoIcon size={29} />}
            onSelect={() => onModeChange("poc")}
            selected={state.mode === "poc"}
            title={messages.poc}
          />
          <ChoiceCard
            description={messages.productionDescription}
            detail={` (${messages.productionUnavailable})`}
            disabled
            icon={<ShieldIcon size={30} />}
            onSelect={() => onModeChange("production")}
            selected={false}
            title={messages.production}
          />
        </div>
      </section>

      <PlatformSelector
        messages={messages}
        onToggle={onPlatformToggle}
        platforms={state.platforms}
      />

      <div className="strategy-grid">
        <section className="form-section strategy-section">
          <h2>
            {messages.infrastructureTitle}
            <InfoIcon size={16} />
          </h2>
          <ChoiceCard
            description={messages.dedicatedDescription}
            detail={` (${messages.recommended})`}
            icon={<NetworkIcon size={27} />}
            onSelect={() => onNetworkChange("dedicated")}
            selected={state.networkStrategy === "dedicated"}
            title={messages.dedicatedNetwork}
          />
          <ChoiceCard
            description={messages.existingDescription}
            icon={<NetworkIcon size={27} />}
            onSelect={() => onNetworkChange("existing")}
            selected={state.networkStrategy === "existing"}
            title={messages.existingVpc}
          />
        </section>

        <section className="form-section strategy-section certificate-section">
          <h2>
            {messages.certificateTitle}
            <InfoIcon size={16} />
          </h2>
          <ChoiceCard
            description={messages.enterpriseCaDescription}
            icon={<ShieldIcon size={27} />}
            onSelect={() => onCertificateChange("enterprise_ca")}
            selected={state.certificateStrategy === "enterprise_ca"}
            title={messages.enterpriseCa}
          />
          <ChoiceCard
            description={messages.publicCertificateDescription}
            icon={<GlobeIcon size={27} />}
            onSelect={() => onCertificateChange("public_trusted")}
            selected={state.certificateStrategy === "public_trusted"}
            title={messages.publicCertificate}
          />
          <ChoiceCard
            description={messages.localPocCaDescription}
            detail={
              state.mode === "production"
                ? ` (${messages.disabledProduction})`
                : ` (${messages.localPocAdminConsole})`
            }
            disabled={localPocDisabled}
            icon={<LockIcon size={26} />}
            onSelect={() => onCertificateChange("local_poc")}
            selected={state.certificateStrategy === "local_poc"}
            title={messages.localPocCa}
          />
        </section>
      </div>
    </>
  );
}
