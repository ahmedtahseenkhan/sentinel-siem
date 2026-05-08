"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const stats = [
  { value: "60+", label: "Machines Deployed" },
  { value: "< 50ms", label: "Alert Latency" },
  { value: "200+", label: "Sigma Rules Built-In" },
  { value: "4", label: "Services, One Platform" },
  { value: "HIPAA", label: "Compliance Ready" },
  { value: "100%", label: "Open Source" },
];

export default function TrustBar() {
  const ref = useScrollReveal();

  return (
    <section
      ref={ref}
      className="fade-section py-16 border-y"
      style={{ borderColor: "var(--border)" }}
      aria-label="Platform statistics"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <p
          className="text-center text-xs font-mono uppercase tracking-widest mb-10"
          style={{ color: "var(--muted)" }}
        >
          Trusted by security teams in production
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-8 stagger-children">
          {stats.map((stat) => (
            <div key={stat.label} className="flex flex-col items-center gap-1 text-center">
              <span
                className="text-2xl font-black font-mono"
                style={{ color: "var(--accent)" }}
              >
                {stat.value}
              </span>
              <span
                className="text-xs uppercase tracking-wider"
                style={{ color: "var(--muted)" }}
              >
                {stat.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
