import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

import { cn } from "@/lib/cn";
import type { Severity } from "@/lib/osint/types";

export function Button({
  variant = "solid",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "solid" | "line" | "ghost" | "danger" }) {
  return (
    <button
      className={cn(
        "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg px-3 text-sm font-medium transition-[opacity,background-color,border-color] duration-150",
        "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variant === "solid" && "bg-accent text-accent-fg hover:opacity-90",
        variant === "line" && "border border-line bg-elevated text-fg hover:border-line-strong",
        variant === "ghost" && "text-fg hover:bg-subtle",
        variant === "danger" && "border border-line text-danger hover:bg-subtle",
        className,
      )}
      {...props}
    />
  );
}

export function TextInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "min-h-11 w-full rounded-lg border border-line bg-subtle px-3 text-sm text-fg",
        "placeholder:text-faint focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info",
        className,
      )}
      {...props}
    />
  );
}

export function SelectInput({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "min-h-11 w-full rounded-lg border border-line bg-subtle px-3 text-sm text-fg",
        "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info",
        className,
      )}
      {...props}
    />
  );
}

export function TextArea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full rounded-lg border border-line bg-subtle px-3 py-2 text-sm text-fg",
        "placeholder:text-faint focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info",
        className,
      )}
      {...props}
    />
  );
}

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn("rounded-3xl border border-line bg-elevated p-4 sm:p-5", className)}>{children}</section>;
}

const SEV: Record<Severity, string> = {
  info: "text-muted border-line",
  low: "text-info border-line",
  medium: "text-warn border-line",
  high: "text-danger border-line",
};

export function Sev({ value }: { value: Severity }) {
  return (
    <span className={cn("inline-flex rounded-md border px-1.5 py-0.5 font-mono text-xs uppercase tracking-wide", SEV[value])}>
      {value}
    </span>
  );
}

export function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-2xl border border-line bg-subtle px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-faint">{label}</p>
      <p className="mt-1 font-mono text-2xl font-medium tabular-nums tracking-tight text-fg">{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </div>
  );
}
