import type { ReactNode } from "react";

interface ChoiceCardProps {
  title: string;
  description: string;
  detail?: string;
  cost?: string;
  selected: boolean;
  disabled?: boolean;
  icon?: ReactNode;
  onSelect: () => void;
}

export function ChoiceCard({
  title,
  description,
  detail,
  cost,
  selected,
  disabled = false,
  icon,
  onSelect,
}: ChoiceCardProps) {
  return (
    <button
      aria-pressed={selected}
      className={[
        "choice-card",
        selected ? "selected" : "",
        disabled ? "disabled" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      disabled={disabled}
      onClick={onSelect}
      type="button"
    >
      <span className="radio-indicator" />
      {icon ? <span className="choice-icon">{icon}</span> : null}
      <span className="choice-copy">
        <strong>
          {title}
          {detail ? <em>{detail}</em> : null}
        </strong>
        {cost ? <em className="choice-cost">{cost}</em> : null}
        <span>{description}</span>
      </span>
    </button>
  );
}
