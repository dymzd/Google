import { useEffect, useRef, useState } from "react";
import type { Locale } from "../lib/setup-state";
import type { Messages } from "../i18n/messages";
import { CheckIcon, ChevronDownIcon, GlobeIcon } from "./Icons";

interface LanguageMenuProps {
  locale: Locale;
  messages: Messages;
  onChange: (locale: Locale) => void;
}

const localeLabels: Record<Locale, keyof Messages["languages"]> = {
  en: "english",
  ja: "japanese",
};

export function LanguageMenu({ locale, messages, onChange }: LanguageMenuProps) {
  const [isOpen, setIsOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handlePointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setIsOpen(false);
    }

    document.addEventListener("pointerdown", handlePointerDown);
    return () => document.removeEventListener("pointerdown", handlePointerDown);
  }, []);

  function selectLocale(nextLocale: Locale) {
    onChange(nextLocale);
    setIsOpen(false);
  }

  return (
    <div className="language-menu" ref={rootRef}>
      <button
        aria-expanded={isOpen}
        aria-haspopup="menu"
        aria-label={messages.languages[localeLabels[locale]]}
        className="language-trigger"
        onClick={() => setIsOpen((open) => !open)}
        type="button"
      >
        <GlobeIcon size={20} />
        <span>{messages.languages[localeLabels[locale]]}</span>
        <ChevronDownIcon className={isOpen ? "rotated" : ""} size={17} />
      </button>
      {isOpen ? (
        <div aria-label="Language" className="language-popover" role="menu">
          {(["en", "ja"] as const).map((option) => (
            <button
              aria-checked={option === locale}
              className="language-option"
              key={option}
              onClick={() => selectLocale(option)}
              role="menuitemradio"
              type="button"
            >
              <span className="language-check">
                {option === locale ? <CheckIcon size={17} /> : null}
              </span>
              <span>{messages.languages[localeLabels[option]]}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
