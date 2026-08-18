import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function IconBase({ size = 22, children, ...props }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      {...props}
    >
      {children}
    </svg>
  );
}

const strokeProps = {
  stroke: "currentColor",
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  strokeWidth: 1.8,
};

export function ShieldNetworkIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M12 2.4 20 5.8v5.7c0 5.1-3.2 8.6-8 10.1-4.8-1.5-8-5-8-10.1V5.8L12 2.4Z" {...strokeProps} />
      <circle cx="12" cy="7.6" r="1.3" fill="currentColor" />
      <circle cx="8.1" cy="11.2" r="1.3" fill="currentColor" />
      <circle cx="14.7" cy="15.4" r="1.3" fill="currentColor" />
      <path d="m11 8.5-1.9 1.7m.1 1.8 4.3 2.7M12.4 8.9l1.7 5.2" {...strokeProps} />
    </IconBase>
  );
}

export function CubeIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="m12 2.8 8 4.4v9.4L12 21l-8-4.4V7.2l8-4.4Z" {...strokeProps} />
      <path d="m4.4 7.5 7.6 4.2 7.6-4.2M12 11.7V21" {...strokeProps} />
    </IconBase>
  );
}

export function PlusCircleIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="M12 8v8M8 12h8" {...strokeProps} />
    </IconBase>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M12 2.8 20 6v5.8c0 4.9-3.1 8.2-8 9.7-4.9-1.5-8-4.8-8-9.7V6l8-3.2Z" {...strokeProps} />
    </IconBase>
  );
}

export function DocumentIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M6 2.8h8l4 4V21H6V2.8Z" {...strokeProps} />
      <path d="M14 2.8v4h4M9 12h6M9 16h6" {...strokeProps} />
    </IconBase>
  );
}

export function BookIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M4 4.5h5.2A2.8 2.8 0 0 1 12 7.3V21a3.5 3.5 0 0 0-3.5-3.5H4v-13Z" {...strokeProps} />
      <path d="M20 4.5h-5.2A2.8 2.8 0 0 0 12 7.3V21a3.5 3.5 0 0 1 3.5-3.5H20v-13Z" {...strokeProps} />
    </IconBase>
  );
}

export function SettingsIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="3" {...strokeProps} />
      <path
        d="m19.2 13.2 1.3 1-.1 2-1.5.8-.7 1.5.5 1.6-1.5 1.3-1.5-.7-1.6.5-.7 1.5-2 .1-1-1.4-1.6-.6-1.5.7-1.5-1.3.5-1.7L5 17l-1.5-.8-.1-2 1.4-1 .1-1.7-1.2-1.1.6-1.9 1.7-.4 1-1.3-.2-1.7 1.8-1 1.4 1h1.7l1.2-1.2 1.8.8.2 1.7 1.4 1 1.7-.3 1 1.7-1 1.4.2 1.7Z"
        {...strokeProps}
      />
    </IconBase>
  );
}

export function LockIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <rect height="10" rx="2" width="14" x="5" y="11" {...strokeProps} />
      <path d="M8 11V8a4 4 0 0 1 8 0v3M12 15v2" {...strokeProps} />
    </IconBase>
  );
}

export function GlobeIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="M3 12h18M12 3c2.4 2.5 3.6 5.5 3.6 9S14.4 18.5 12 21c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3Z" {...strokeProps} />
    </IconBase>
  );
}

export function ChevronDownIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="m7 9.5 5 5 5-5" {...strokeProps} />
    </IconBase>
  );
}

export function HelpIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="M9.7 9a2.5 2.5 0 1 1 3.2 2.4c-.9.4-.9 1.1-.9 1.8M12 17.2h.01" {...strokeProps} />
    </IconBase>
  );
}

export function InfoIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="M12 10.8v5M12 7.5h.01" {...strokeProps} />
    </IconBase>
  );
}

export function NetworkIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="5" r="2" {...strokeProps} />
      <circle cx="5" cy="18" r="2" {...strokeProps} />
      <circle cx="19" cy="18" r="2" {...strokeProps} />
      <path d="m11 6.8-5 9.4m7-9.4 5 9.4M7 18h10" {...strokeProps} />
    </IconBase>
  );
}

export function CheckIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="m5 12.5 4.2 4L19 7" {...strokeProps} />
    </IconBase>
  );
}

export function ArrowRightIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M5 12h14M14 7l5 5-5 5" {...strokeProps} />
    </IconBase>
  );
}

export function MonitorIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <rect height="13" rx="1.5" width="19" x="2.5" y="3.5" {...strokeProps} />
      <path d="M8 21h8M12 16.5V21" {...strokeProps} />
    </IconBase>
  );
}

export function UsersIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="9" cy="8" r="3" {...strokeProps} />
      <circle cx="17" cy="9.5" r="2.3" {...strokeProps} />
      <path d="M3.5 20v-2.2A4.8 4.8 0 0 1 8.3 13h1.4a4.8 4.8 0 0 1 4.8 4.8V20M15.2 14.2h1.4a3.9 3.9 0 0 1 3.9 3.9V20" {...strokeProps} />
    </IconBase>
  );
}

export function ClipboardIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M8 5H5v16h14V5h-3" {...strokeProps} />
      <rect height="4" rx="1" width="8" x="8" y="3" {...strokeProps} />
      <path d="M8 11h8M8 15h8" {...strokeProps} />
    </IconBase>
  );
}

export function CloudIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="M6.5 19h11a4 4 0 0 0 .4-8A6 6 0 0 0 6.5 9.2 4.9 4.9 0 0 0 6.5 19Z" {...strokeProps} />
    </IconBase>
  );
}

export function CodeIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <path d="m8.5 7-5 5 5 5M15.5 7l5 5-5 5M13.5 4 10.5 20" {...strokeProps} />
    </IconBase>
  );
}

export function CheckCircleIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="m8.5 12 2.3 2.3 4.7-4.7" {...strokeProps} />
    </IconBase>
  );
}

export function ExclamationCircleIcon(props: IconProps) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <path d="M12 8v4M12 16h.01" {...strokeProps} />
    </IconBase>
  );
}

