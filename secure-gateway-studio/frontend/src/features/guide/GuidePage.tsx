import type { Messages } from "../../i18n/messages";
import { CheckIcon, CodeIcon, InfoIcon, LockIcon, NetworkIcon, ShieldIcon } from "../../components/Icons";

interface GuidePageProps {
  messages: Messages;
}

export function GuidePage({ messages }: GuidePageProps) {
  const guide = messages.guide;

  return (
    <main className="guide-page">
      <header className="guide-heading">
        <p className="eyebrow">{guide.eyebrow}</p>
        <h1>{guide.title}</h1>
        <p>{guide.intro}</p>
      </header>

      <aside className="guide-poc-notice">
        <InfoIcon size={24} />
        <div>
          <strong>{guide.pocNoticeTitle}</strong>
          <p>{guide.pocNoticeBody}</p>
        </div>
      </aside>

      {/* TOP SECTION: Quick Overview & Architecture Decisions */}
      <section className="architecture-section" aria-labelledby="architecture-title">
        <header className="architecture-heading">
          <p className="eyebrow">Quick Overview & Architecture Selection</p>
          <h2 id="architecture-title">{guide.architectureTitle}</h2>
          <p>{guide.architectureIntro}</p>
        </header>
        <div className="architecture-grid">
          {guide.architectures.map((architecture) => (
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

      {/* TOP SECTION: Implementation Inventory */}
      <section className="implementation-section" aria-labelledby="implementation-title">
        <header className="architecture-heading">
          <p className="eyebrow">Implementation inventory</p>
          <h2 id="implementation-title">{guide.implementationTitle}</h2>
          <p>{guide.implementationIntro}</p>
        </header>
        <div className="implementation-grid">
          {guide.implementationGroups.map((group) => (
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

      {/* BOTTOM SECTION: Step-by-Step Technical Deep Dive & REST API Reference */}
      <section className="technical-deep-dive-section" aria-labelledby="technical-deep-dive-title">
        <header className="architecture-heading">
          <p className="eyebrow">Technical Reference & API Calls</p>
          <h2 id="technical-deep-dive-title">{guide.technicalDeepDiveTitle}</h2>
          <p>{guide.technicalDeepDiveIntro}</p>
        </header>

        <ol className="guide-steps">
          {guide.steps.map((step, index) => (
            <li className="guide-step technical-step-card" key={step.title}>
              <div className="guide-step-number" aria-hidden="true">
                {index + 1}
              </div>
              <div className="guide-step-copy">
                <div className="step-title-group">
                  <span className="step-badge">{guide.stepLabel(index + 1)}</span>
                  <h2>{step.title}</h2>
                  {step.subtitle && <p className="step-subtitle">{step.subtitle}</p>}
                </div>
                <p className="step-summary-text">{step.summary}</p>

                <div className="step-section-block">
                  <h4 className="step-subheading">
                    <CheckIcon size={16} />
                    <span>Checklist & Actions</span>
                  </h4>
                  <ul className="step-actions-list">
                    {step.actions.map((action) => (
                      <li key={action}>
                        <CheckIcon size={16} />
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {step.optionsBehavior && step.optionsBehavior.length > 0 && (
                  <div className="step-section-block">
                    <h4 className="step-subheading">
                      <NetworkIcon size={16} />
                      <span>{guide.optionsBehaviorLabel}</span>
                    </h4>
                    <div className="options-behavior-grid">
                      {step.optionsBehavior.map((opt) => (
                        <div className="option-behavior-card" key={opt.name}>
                          <strong>{opt.name}</strong>
                          <p>{opt.behavior}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {step.apiCalls && step.apiCalls.length > 0 && (
                  <div className="step-section-block">
                    <h4 className="step-subheading">
                      <CodeIcon size={16} />
                      <span>{guide.apiCallsLabel}</span>
                    </h4>
                    <div className="api-calls-list">
                      {step.apiCalls.map((api) => (
                        <div className="api-call-row" key={`${api.method}-${api.endpoint}`}>
                          <span className={`api-badge api-badge-${api.method.toLowerCase()}`}>
                            {api.method}
                          </span>
                          <div className="api-call-content">
                            <code className="api-endpoint">{api.endpoint}</code>
                            <p className="api-purpose">{api.purpose}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {step.safetyNote && (
                  <div className="step-safety-note">
                    <ShieldIcon size={18} />
                    <div>
                      <strong>{guide.safetyGuardrailLabel}</strong>
                      <p>{step.safetyNote}</p>
                    </div>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* FAQ & Troubleshooting Section */}
      {guide.faqs && guide.faqs.length > 0 && (
        <section className="faq-section" aria-labelledby="faq-title">
          <header className="architecture-heading">
            <p className="eyebrow">Troubleshooting & Best Practices</p>
            <h2 id="faq-title">{guide.faqTitle}</h2>
            <p>{guide.faqIntro}</p>
          </header>

          <div className="faq-grid">
            {guide.faqs.map((faq) => (
              <details className="faq-card" key={faq.id}>
                <summary className="faq-summary">
                  <span className="faq-category-tag">{faq.category}</span>
                  <strong className="faq-question">{faq.question}</strong>
                </summary>
                <div className="faq-content">
                  <p className="faq-answer">{faq.answer}</p>
                  {faq.checklist && faq.checklist.length > 0 && (
                    <div className="faq-checklist-box">
                      <div className="faq-checklist-title">
                        <CheckIcon size={16} />
                        <span>確認チェックリスト・解決手順</span>
                      </div>
                      <ul className="faq-checklist">
                        {faq.checklist.map((item, idx) => (
                          <li key={idx}>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </details>
            ))}
          </div>
        </section>
      )}
    </main>
  );
}

