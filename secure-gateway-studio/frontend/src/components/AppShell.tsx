import type { ReactNode } from "react";
import type { Locale } from "../lib/setup-state";
import type { Messages } from "../i18n/messages";
import type { OperationsView } from "../features/operations/OperationsPage";
import {
  BookIcon,
  CubeIcon,
  DocumentIcon,
  HelpIcon,
  LockIcon,
  PlusCircleIcon,
  ShieldNetworkIcon,
} from "./Icons";
import { LanguageMenu } from "./LanguageMenu";

export type AppView = "setup" | OperationsView | "guide";

interface AppShellProps {
  children: ReactNode;
  locale: Locale;
  messages: Messages;
  activeView: AppView;
  cloudProject: string;
  workspaceAdmin: string;
  onLocaleChange: (locale: Locale) => void;
  onNavigate: (view: AppView) => void;
}

const navIcons = [CubeIcon, PlusCircleIcon, DocumentIcon];

export function AppShell({
  children,
  locale,
  messages,
  activeView,
  cloudProject,
  workspaceAdmin,
  onLocaleChange,
  onNavigate,
}: AppShellProps) {
  const navItems: Array<{
    label: string;
    view: "setup" | OperationsView;
  }> = [
    { label: messages.nav.deployments, view: "deployments" },
    { label: messages.nav.newSetup, view: "setup" },
    { label: messages.nav.evidence, view: "evidence" },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark" aria-label={messages.productName}>
          <ShieldNetworkIcon size={60} />
        </div>
        <nav aria-label="Primary navigation" className="primary-nav">
          {navItems.map((item, index) => {
            const Icon = navIcons[index];
            const active = activeView === item.view;
            return (
              <button
                aria-current={active ? "page" : undefined}
                className={active ? "nav-item active" : "nav-item"}
                key={item.view}
                onClick={() => onNavigate(item.view)}
                type="button"
              >
                <Icon size={29} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <nav aria-label="Guide navigation" className="guide-nav">
          <button
            aria-current={activeView === "guide" ? "page" : undefined}
            className={
              activeView === "guide" ? "nav-item active" : "nav-item"
            }
            onClick={() => onNavigate("guide")}
            type="button"
          >
            <BookIcon size={29} />
            <span>{messages.nav.guide}</span>
          </button>
        </nav>
      </aside>

      <div className="app-frame">
        <header className="topbar">
          <div className="product-title">
            <strong>{messages.productName}</strong>
            <span className="local-status">
              <LockIcon size={16} />
              {messages.localOnly}
            </span>
          </div>
          <div className="header-actions">
            <div className="identity-control">
              <span aria-hidden="true" className="google-cloud-symbol">
                G
              </span>
              <span className="identity-copy">
                <span>{messages.cloudIdentity}</span>
                <strong>{cloudProject || messages.cloudProject}</strong>
              </span>
            </div>
            <div className="identity-control">
              <span aria-hidden="true" className="workspace-symbol">
                A
              </span>
              <span className="identity-copy">
                <span>{messages.workspaceIdentity}</span>
                <strong>{workspaceAdmin || messages.adminEmail}</strong>
              </span>
            </div>
            <LanguageMenu
              locale={locale}
              messages={messages}
              onChange={onLocaleChange}
            />
            <a
              className="help-control"
              href="https://docs.cloud.google.com/chrome-enterprise-premium/docs/security-gateway-private-web-apps"
              rel="noreferrer"
              target="_blank"
            >
              <HelpIcon size={20} />
              <span>{messages.help}</span>
            </a>
          </div>
        </header>
        {children}
      </div>
    </div>
  );
}
