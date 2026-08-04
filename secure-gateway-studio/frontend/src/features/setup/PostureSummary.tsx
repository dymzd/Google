import type { Messages } from "../../i18n/messages";
import type { SetupState } from "../../lib/setup-state";
import { countSelectedPlatforms } from "../../lib/setup-state";
import {
  CheckIcon,
  ClipboardIcon,
  CloudIcon,
  CodeIcon,
  LockIcon,
  MonitorIcon,
  NetworkIcon,
  ShieldIcon,
  ShieldNetworkIcon,
  UsersIcon,
} from "../../components/Icons";

interface PostureSummaryProps {
  messages: Messages;
  state: SetupState;
}

export function PostureSummary({ messages, state }: PostureSummaryProps) {
  const mode = state.mode === "production" ? messages.production : messages.poc;
  const network =
    state.networkStrategy === "dedicated"
      ? messages.dedicatedNetwork
      : messages.existingVpc;
  const certificate =
    state.backendKind === "direct_https"
      ? messages.applicationOwnedTls
      : state.certificateStrategy === "enterprise_ca"
      ? messages.enterpriseCa
      : state.certificateStrategy === "public_trusted"
        ? messages.publicCertificate
        : messages.localPocCa;

  return (
    <aside className="posture-panel">
      <h2>
        <ShieldNetworkIcon size={27} />
        {messages.posture}
      </h2>
      <dl className="posture-list">
        <div>
          <ClipboardIcon size={24} />
          <span>
            <dt>{messages.mode}</dt>
            <dd>{mode}</dd>
          </span>
        </div>
        <div>
          <MonitorIcon size={25} />
          <span>
            <dt>{messages.managedPlatforms}</dt>
            <dd>{messages.platformCount(countSelectedPlatforms(state.platforms))}</dd>
          </span>
        </div>
        <div>
          <NetworkIcon size={25} />
          <span>
            <dt>{messages.infrastructure}</dt>
            <dd>{network}</dd>
          </span>
        </div>
        <div>
          <ShieldIcon size={25} />
          <span>
            <dt>{messages.certificateStrategy}</dt>
            <dd>{certificate}</dd>
          </span>
        </div>
        <div>
          <UsersIcon size={25} />
          <span>
            <dt>{messages.targetOu}</dt>
            <dd>{messages.testOuAvailable}</dd>
          </span>
          <span className="success-check">
            <CheckIcon size={17} />
          </span>
        </div>
      </dl>

      <div className="gate-section">
        <h3>{messages.deploymentGates}</h3>
        <ul>
          {state.backendKind === "direct_https" ? (
            <>
              <li>
                <NetworkIcon size={19} />
                <span>{messages.upstreamVpc}</span>
                <strong>{messages.required}</strong>
              </li>
              <li>
                <CloudIcon size={19} />
                <span>{messages.privateDnsRoute}</span>
                <strong>{messages.required}</strong>
              </li>
            </>
          ) : (
            <>
              <li>
                <LockIcon size={19} />
                <span>{messages.noExternalIps}</span>
                <strong>{messages.required}</strong>
              </li>
              <li>
                <CloudIcon size={19} />
                <span>{messages.cloudNat}</span>
                <strong>{messages.required}</strong>
              </li>
            </>
          )}
          <li>
            <CodeIcon size={19} />
            <span>{messages.apiPreflight}</span>
            <em>{messages.willValidate}</em>
          </li>
          <li>
            <UsersIcon size={19} />
            <span>{messages.approval}</span>
            <strong className="warning">{messages.required}</strong>
          </li>
        </ul>
        <p>{messages.gateNote}</p>
      </div>
    </aside>
  );
}
