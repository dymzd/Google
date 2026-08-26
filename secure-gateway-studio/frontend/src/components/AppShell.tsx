import { useState, type ReactNode } from "react";
import type { Locale } from "../lib/setup-state";
import type { Messages } from "../i18n/messages";
import type { OperationsView } from "../features/operations/OperationsPage";
import {
  BookIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CubeIcon,
  DocumentIcon,
  HelpIcon,
  LockIcon,
  PlusCircleIcon,
  ShieldNetworkIcon,
  SignOutIcon,
} from "./Icons";
import { LanguageMenu } from "./LanguageMenu";

export type AppView = "setup" | OperationsView | "guide" | "cepDeployer";

interface AppShellProps {
  children: ReactNode;
  locale: Locale;
  messages: Messages;
  activeView: AppView;
  cloudProject: string;
  workspaceAdmin: string;
  onLocaleChange: (locale: Locale) => void;
  onNavigate: (view: AppView) => void;
  onSignOut: () => void;
  showCepDeployer: boolean;
}

export function AppShell({
  children,
  locale,
  messages,
  activeView,
  cloudProject,
  workspaceAdmin,
  onLocaleChange,
  onNavigate,
  onSignOut,
  showCepDeployer,
}: AppShellProps) {
  const isSgwActive =
    activeView === "setup" ||
    activeView === "deployments" ||
    activeView === "evidence" ||
    activeView === "guide";

  const [sgwMenuOpen, setSgwMenuOpen] = useState(false);

  const sgwSubItems: Array<{
    label: string;
    view: AppView;
    icon: typeof CubeIcon;
  }> = [
    { label: messages.nav.deployments, view: "deployments", icon: CubeIcon },
    { label: messages.nav.newSetup, view: "setup", icon: PlusCircleIcon },
    { label: messages.nav.evidence, view: "evidence", icon: DocumentIcon },
    { label: messages.nav.guide, view: "guide", icon: BookIcon },
  ];

  const handleToggleSgw = () => {
    if (!isSgwActive) {
      setSgwMenuOpen(true);
      onNavigate("setup");
    } else {
      setSgwMenuOpen((open) => !open);
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark" aria-label={messages.productName}>
          <ShieldNetworkIcon size={44} />
        </div>
        <nav aria-label="Primary navigation" className="primary-nav">
          {showCepDeployer && (
            <button
              aria-label={messages.nav.easyPoc}
              aria-current={activeView === "cepDeployer" ? "page" : undefined}
              className={activeView === "cepDeployer" ? "nav-item active" : "nav-item"}
              onClick={() => onNavigate("cepDeployer")}
              type="button"
            >
              <ShieldNetworkIcon size={24} />
              <span>{messages.nav.easyPoc}</span>
            </button>
          )}

          {/* 2. Secure Gateway Deployer (Collapsible dropdown parent) */}
          <div className={`nav-dropdown-group ${isSgwActive ? "active-parent" : ""} ${sgwMenuOpen ? "open" : ""}`}>
            <button
              aria-label={messages.nav.sgwDeployer}
              aria-expanded={sgwMenuOpen}
              className={`nav-item nav-dropdown-trigger ${isSgwActive ? "active" : ""}`}
              onClick={handleToggleSgw}
              type="button"
            >
              <CubeIcon size={24} />
              <div className="nav-label-with-arrow">
                <span>{messages.nav.sgwDeployer}</span>
                {sgwMenuOpen ? <ChevronUpIcon size={14} /> : <ChevronDownIcon size={14} />}
              </div>
            </button>

            {/* Submenu containing the 4 SGW tabs */}
            {sgwMenuOpen && (
              <div className="nav-submenu">
                {sgwSubItems.map((item) => {
                  const SubIcon = item.icon;
                  const active = activeView === item.view;
                  return (
                    <button
                      aria-current={active ? "page" : undefined}
                      className={`nav-subitem ${active ? "active" : ""}`}
                      key={item.view}
                      onClick={() => {
                        setSgwMenuOpen(false);
                        onNavigate(item.view);
                      }}
                      type="button"
                    >
                      <SubIcon size={15} />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </nav>

        <div className="sidebar-bottom">
          <button
            className="nav-item sidebar-sign-out"
            onClick={onSignOut}
            title={messages.signOut}
            type="button"
          >
            <SignOutIcon size={22} />
            <span>{messages.signOut}</span>
          </button>
        </div>
      </aside>

      <div className="app-frame">
        <header className="topbar">
          <div className="product-title">
            <div className="product-title-headings">
              <strong className="product-main-title">{messages.mainTitle}</strong>
              <span className="product-sub-title">{messages.productName}</span>
            </div>
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
