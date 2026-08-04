import type { Messages } from "../../i18n/messages";
import { CheckIcon, InfoIcon } from "../../components/Icons";

interface GuidePageProps {
  messages: Messages;
}

export function GuidePage({ messages }: GuidePageProps) {
  return (
    <main className="guide-page">
      <header className="guide-heading">
        <p className="eyebrow">{messages.guide.eyebrow}</p>
        <h1>{messages.guide.title}</h1>
        <p>{messages.guide.intro}</p>
      </header>

      <aside className="guide-poc-notice">
        <InfoIcon size={24} />
        <div>
          <strong>{messages.guide.pocNoticeTitle}</strong>
          <p>{messages.guide.pocNoticeBody}</p>
        </div>
      </aside>

      <section className="architecture-section" aria-labelledby="architecture-title">
        <header className="architecture-heading">
          <p className="eyebrow">Architecture</p>
          <h2 id="architecture-title">{messages.guide.architectureTitle}</h2>
          <p>{messages.guide.architectureIntro}</p>
        </header>
        <div className="architecture-grid">
          {messages.guide.architectures.map((architecture) => (
            <article className="architecture-card" key={architecture.title}>
              <div className="architecture-card-heading">
                <span>{architecture.eyebrow}</span>
                <h3>{architecture.title}</h3>
                <p>{architecture.summary}</p>
              </div>
              <div className="architecture-flow" role="list">
                {architecture.nodes.map((node, index) => (
                  <div className="architecture-flow-item" key={node.label} role="listitem">
                    <div className="architecture-node">
                      <strong>{node.label}</strong>
                      <small>{node.detail}</small>
                    </div>
                    {index < architecture.nodes.length - 1 ? (
                      <span className="architecture-arrow" aria-hidden="true">
                        <i />
                      </span>
                    ) : null}
                  </div>
                ))}
              </div>
              <div className="architecture-supports">
                {architecture.supports.map((support) => (
                  <div className="architecture-support" key={support.label}>
                    <span aria-hidden="true" />
                    <div>
                      <strong>{support.label}</strong>
                      <small>{support.detail}</small>
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="implementation-section" aria-labelledby="implementation-title">
        <header className="architecture-heading">
          <p className="eyebrow">Implementation inventory</p>
          <h2 id="implementation-title">{messages.guide.implementationTitle}</h2>
          <p>{messages.guide.implementationIntro}</p>
        </header>
        <div className="implementation-grid">
          {messages.guide.implementationGroups.map((group) => (
            <article className="implementation-card" key={group.title}>
              <div className="implementation-card-heading">
                <span>{group.eyebrow}</span>
                <h3>{group.title}</h3>
              </div>
              <ul>
                {group.items.map((item) => (
                  <li key={item}>
                    <CheckIcon size={17} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <ol className="guide-steps">
        {messages.guide.steps.map((step, index) => (
          <li className="guide-step" key={step.title}>
            <div className="guide-step-number" aria-hidden="true">
              {index + 1}
            </div>
            <div className="guide-step-copy">
              <span>{messages.guide.stepLabel(index + 1)}</span>
              <h2>{step.title}</h2>
              <p>{step.summary}</p>
              <ul>
                {step.actions.map((action) => (
                  <li key={action}>
                    <CheckIcon size={18} />
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          </li>
        ))}
      </ol>
    </main>
  );
}
