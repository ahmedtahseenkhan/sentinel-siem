"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const sigmaRule = `title: Suspicious PowerShell Encoded Command
id: f4bbd493-b796-416e-bbf2-121235a9e739
status: stable
description: Detects suspicious PowerShell encoded commands
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001`;

const alertOutput = `[2026-05-03 14:32:07] ALERT FIRED
─────────────────────────────────────
Rule      : Suspicious PowerShell Encoded Command
Level     : HIGH
Host      : DESKTOP-19
User      : CORP\\john.doe
PID       : 4892
MITRE     : T1059.001 (PowerShell)
─────────────────────────────────────
CommandLine:
  powershell.exe -enc JABjAD0ATg...

Action    : Logged + Analyst notified
Response  : Pending approval`;

export default function DetectionShowcase() {
  const ref = useScrollReveal();

  return (
    <section
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      aria-labelledby="detection-heading"
    >
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          {/* Copy */}
          <div>
            <p
              className="text-xs font-mono uppercase tracking-widest mb-3"
              style={{ color: "var(--accent)" }}
            >
              Rule Engine
            </p>
            <h2
              id="detection-heading"
              className="text-4xl sm:text-5xl font-black tracking-tight mb-6 text-balance"
              style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
            >
              Community rules.
              <br />
              <span style={{ color: "#f6b73c" }}>Native execution.</span>
            </h2>
            <p
              className="text-base leading-relaxed mb-8 text-pretty"
              style={{ color: "var(--muted)" }}
            >
              WatchTower parses Sigma YAML directly into executable Go
              matchers — no sigmac, no external tools, no SIEM lock-in. Drop
              in any community rule and it fires immediately against your
              live event stream.
            </p>

            <ul className="space-y-4" role="list">
              {[
                {
                  icon: "⚡",
                  title: "Real-time evaluation",
                  desc: "Every event matched in-memory as it arrives — sub-50ms alert latency.",
                },
                {
                  icon: "📦",
                  title: "200+ rules bundled",
                  desc: "Curated Sigma rules covering Windows, Linux, network, and cloud.",
                },
                {
                  icon: "🔗",
                  title: "MITRE ATT&CK mapped",
                  desc: "Automatic tactic and technique tagging on every detection.",
                },
              ].map((item) => (
                <li key={item.title} className="flex gap-4">
                  <span className="text-xl flex-shrink-0 mt-0.5" aria-hidden="true">
                    {item.icon}
                  </span>
                  <div>
                    <strong
                      className="text-sm font-semibold block"
                      style={{ color: "var(--text)" }}
                    >
                      {item.title}
                    </strong>
                    <span className="text-sm" style={{ color: "var(--muted)" }}>
                      {item.desc}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          {/* Terminals */}
          <div className="space-y-4">
            <div
              className="terminal"
              aria-label="Sigma rule YAML example"
            >
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
                  powershell-encoded.yml
                </span>
              </div>
              <pre
                className="p-5 text-xs leading-relaxed overflow-x-auto"
                style={{ color: "#e6edf3" }}
              >
                <code>
                  {sigmaRule.split("\n").map((line, i) => {
                    const isKey = line.match(/^[a-z]/) && line.includes(":");
                    const isValue = line.match(/^  (- |[a-z])/);
                    const isComment = line.startsWith("#");
                    let color = "#e6edf3";
                    if (isKey) color = "#58a6ff";
                    else if (isComment) color = "#8b949e";
                    else if (isValue && line.includes("attack")) color = "#f6b73c";

                    return (
                      <span
                        key={i}
                        style={{ color, display: "block" }}
                      >
                        {line || " "}
                      </span>
                    );
                  })}
                </code>
              </pre>
            </div>

            <div
              className="terminal"
              aria-label="Alert output example"
              style={{ border: "1px solid rgba(248,81,73,0.3)" }}
            >
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
                  watchtower.log
                </span>
                <span
                  className="ml-auto text-xs px-2 py-0.5 rounded"
                  style={{ background: "rgba(248,81,73,0.15)", color: "#f85149" }}
                >
                  LIVE
                </span>
              </div>
              <pre
                className="p-5 text-xs leading-relaxed overflow-x-auto"
                style={{ color: "#e6edf3" }}
              >
                <code>
                  {alertOutput.split("\n").map((line, i) => {
                    let color = "#e6edf3";
                    if (line.includes("HIGH")) color = "#d29922";
                    if (line.includes("ALERT FIRED")) color = "#f85149";
                    if (line.includes("T1059")) color = "#f6b73c";
                    if (line.includes("Action") || line.includes("Response")) color = "#3fb950";
                    if (line.startsWith("─")) color = "#30363d";
                    if (line.startsWith("Rule") || line.startsWith("Level") || line.startsWith("Host") || line.startsWith("User") || line.startsWith("PID") || line.startsWith("MITRE")) color = "#8b949e";

                    return (
                      <span key={i} style={{ color, display: "block" }}>
                        {line || " "}
                      </span>
                    );
                  })}
                </code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
