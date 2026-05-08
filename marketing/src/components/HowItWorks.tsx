"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const steps = [
  {
    number: "01",
    title: "Deploy WatchNode",
    description:
      "Install the lightweight Go agent on any Windows or Linux endpoint. Bulk-deploy to 60+ machines via PowerShell in under an hour using the included automation scripts.",
    detail: "Agent streams → gRPC → WatchTower",
    color: "#58a6ff",
    code: `# Deploy to all machines
.\\deploy-to-all-machines.ps1 \\
  -ServerIP 10.0.0.10 \\
  -CsvFile machines.csv

✓ 60 agents online`,
  },
  {
    number: "02",
    title: "Detect with Sigma Rules",
    description:
      "WatchTower evaluates every event stream against your Sigma rule library. Community rules load instantly — no conversion step, no custom DSL to learn.",
    detail: "200+ rules · Real-time · Zero config",
    color: "#f6b73c",
    code: `title: Mimikatz LSASS Access
status: stable
detection:
  selection:
    EventID: 10
    TargetImage|endswith: lsass.exe
    GrantedAccess: '0x1010'
condition: selection

→ CRITICAL alert fired`,
  },
  {
    number: "03",
    title: "Investigate & Respond",
    description:
      "The SOC dashboard surfaces MITRE ATT&CK mappings, risk scores, and compliance gaps. Active response playbooks fire automatically — or on analyst command.",
    detail: "OpenSearch · MITRE · HIPAA · Active Response",
    color: "#3fb950",
    code: `[ALERT] Mimikatz LSASS Access
Host    : WIN-SRV-04
MITRE   : T1003.001
Action  : Isolating host...
Status  : ✓ Host quarantined`,
  },
];

export default function HowItWorks() {
  const ref = useScrollReveal();

  return (
    <section
      id="how-it-works"
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      style={{ background: "var(--surface)" }}
      aria-labelledby="how-heading"
    >
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-20">
          <p
            className="text-xs font-mono uppercase tracking-widest mb-3"
            style={{ color: "var(--accent)" }}
          >
            How It Works
          </p>
          <h2
            id="how-heading"
            className="text-4xl sm:text-5xl font-black tracking-tight text-balance"
            style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
          >
            From zero to detected
            <br />
            <span style={{ color: "var(--muted)", fontWeight: 600, fontSize: "0.75em" }}>
              in three steps.
            </span>
          </h2>
        </div>

        {/* Steps */}
        <div className="space-y-16 stagger-children">
          {steps.map((step, i) => (
            <article
              key={step.number}
              className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center"
            >
              {/* Text side */}
              <div className={i % 2 === 1 ? "lg:order-2" : "lg:order-1"}>
                <div className="flex items-center gap-4 mb-4">
                  <span
                    className="text-5xl font-black font-mono opacity-20 leading-none"
                    style={{ color: step.color }}
                    aria-hidden="true"
                  >
                    {step.number}
                  </span>
                  <div
                    className="h-px flex-1"
                    style={{ background: `${step.color}30` }}
                    aria-hidden="true"
                  />
                </div>
                <h3
                  className="text-2xl sm:text-3xl font-bold mb-4 text-balance"
                  style={{ color: "var(--text)", letterSpacing: "-0.02em" }}
                >
                  {step.title}
                </h3>
                <p
                  className="text-base leading-relaxed mb-4 text-pretty"
                  style={{ color: "var(--muted)" }}
                >
                  {step.description}
                </p>
                <div
                  className="inline-flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full border"
                  style={{
                    color: step.color,
                    borderColor: `${step.color}30`,
                    background: `${step.color}08`,
                  }}
                >
                  {step.detail}
                </div>
              </div>

              {/* Terminal side */}
              <div className={i % 2 === 1 ? "lg:order-1" : "lg:order-2"}>
                <div className="terminal" aria-label={`Code example for ${step.title}`}>
                  <div className="terminal-header">
                    <span
                      className="terminal-dot"
                      style={{ background: "#f85149" }}
                      aria-hidden="true"
                    />
                    <span
                      className="terminal-dot"
                      style={{ background: "#d29922" }}
                      aria-hidden="true"
                    />
                    <span
                      className="terminal-dot"
                      style={{ background: "#3fb950" }}
                      aria-hidden="true"
                    />
                    <span
                      className="ml-3 text-xs"
                      style={{ color: "var(--muted)" }}
                    >
                      sentinel-core
                    </span>
                  </div>
                  <pre
                    className="p-5 text-xs leading-relaxed overflow-x-auto"
                    style={{ color: "#e6edf3" }}
                  >
                    <code>{step.code}</code>
                  </pre>
                </div>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
