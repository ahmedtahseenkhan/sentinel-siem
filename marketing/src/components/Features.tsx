"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const features = [
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
    title: "Sigma Rule Engine",
    description:
      "Native parsing and execution of community Sigma YAML rules — no conversion tools, no lock-in. Deploy hundreds of detections on day one.",
    accent: "#58a6ff",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <rect x="2" y="3" width="20" height="14" rx="2" />
        <path d="M8 21h8M12 17v4" />
        <path d="M6 8h.01M9 8h6" />
        <path d="M6 11h.01M9 11h6" />
      </svg>
    ),
    title: "Deep Endpoint Telemetry",
    description:
      "WatchNode agents stream FIM, registry changes, process trees, network connections, and Docker events via gRPC — continuously.",
    accent: "#f6b73c",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />
      </svg>
    ),
    title: "MITRE ATT&CK Mapping",
    description:
      "Every alert is mapped to a MITRE ATT&CK tactic and technique. Instantly know the adversary playbook behind each detection.",
    accent: "#3fb950",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <circle cx="12" cy="12" r="3" />
        <path d="M3 12h3M18 12h3M12 3v3M12 18v3" />
        <path d="M5.64 5.64l2.12 2.12M16.24 16.24l2.12 2.12M5.64 18.36l2.12-2.12M16.24 7.76l2.12-2.12" />
      </svg>
    ),
    title: "Automated Active Response",
    description:
      "WatchTower executes configurable playbooks on detection — isolate hosts, kill processes, block IPs — without human intervention.",
    accent: "#f85149",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    title: "Compliance & SCA",
    description:
      "Built-in HIPAA compliance tracking and Security Configuration Assessment evaluates every endpoint against hardening policies.",
    accent: "#d29922",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6" aria-hidden="true">
        <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
      </svg>
    ),
    title: "OpenSearch Powered",
    description:
      "WatchVault indexes every event into OpenSearch — petabyte-scale storage, sub-second queries, and full Kibana-compatible dashboards.",
    accent: "#58a6ff",
  },
];

export default function Features() {
  const ref = useScrollReveal();

  return (
    <section
      id="features"
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      aria-labelledby="features-heading"
    >
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <p
            className="text-xs font-mono uppercase tracking-widest mb-3"
            style={{ color: "var(--accent)" }}
          >
            Capabilities
          </p>
          <h2
            id="features-heading"
            className="text-4xl sm:text-5xl font-black tracking-tight text-balance"
            style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
          >
            Everything your SOC needs.
            <br />
            <span style={{ color: "var(--muted)", fontWeight: 600, fontSize: "0.75em" }}>
              Nothing it doesn&apos;t.
            </span>
          </h2>
        </div>

        {/* Features grid — asymmetric */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px stagger-children"
          style={{ background: "var(--border)" }}
        >
          {features.map((feature) => (
            <article
              key={feature.title}
              className="card-glow p-8 group"
              style={{ background: "var(--bg)" }}
            >
              <div
                className="size-12 rounded-xl flex items-center justify-center mb-5 transition-colors duration-300"
                style={{
                  background: `${feature.accent}14`,
                  color: feature.accent,
                  border: `1px solid ${feature.accent}25`,
                }}
              >
                {feature.icon}
              </div>
              <h3
                className="text-lg font-bold mb-3 text-balance"
                style={{ color: "var(--text)" }}
              >
                {feature.title}
              </h3>
              <p
                className="text-sm leading-relaxed text-pretty"
                style={{ color: "var(--muted)" }}
              >
                {feature.description}
              </p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
