"use client";

import { useState } from "react";
import { useScrollReveal } from "@/hooks/useScrollReveal";

const faqs = [
  {
    q: "How is Sentinel Core different from Wazuh or Elastic Security?",
    a: "Sentinel Core natively parses and executes Sigma YAML rules in Go — no external conversion tools, no SIEM DSL to learn. The entire stack (agent, manager, indexer, dashboard) is a single cohesive system built from scratch, making it easier to deploy and maintain than Wazuh's sprawling module ecosystem.",
  },
  {
    q: "Can I run this on Windows endpoints only?",
    a: "WatchNode agents run on both Windows and Linux. The bulk deployment tooling (PowerShell scripts, nssm service management) is optimized for Windows fleets, but Linux agents use standard systemd service management.",
  },
  {
    q: "What does the Sigma rule engine support?",
    a: "WatchTower supports Sigma condition logic, field modifiers (contains, endswith, startswith, re), logsource routing, and MITRE ATT&CK tagging. Community rules from the official SigmaHQ repository load without modification.",
  },
  {
    q: "How much does it cost to run at scale?",
    a: "The platform itself is free and open source. Infrastructure costs depend on your OpenSearch deployment — a 60-endpoint deployment with 90-day retention typically runs on a single mid-range server (8 cores, 32GB RAM, 2TB SSD).",
  },
  {
    q: "Is active response safe to enable in production?",
    a: "Active response actions (host isolation, process kill) are configured per-rule and can be set to require analyst approval before execution. You control what fires automatically vs. what requires a human decision.",
  },
  {
    q: "How do I deploy to 60 machines at once?",
    a: "Use the included PowerShell deployment script (deploy-to-all-machines.ps1) with a CSV of machine names and credentials. The script installs WatchNode as a Windows service via nssm, configures the server IP, and starts the agent — typically completing in under 15 minutes for a 60-machine fleet.",
  },
  {
    q: "Does it support HIPAA compliance reporting?",
    a: "Yes. The dashboard includes a dedicated HIPAA compliance view that maps detected events and configuration gaps to specific HIPAA controls, generates exportable reports, and tracks compliance trends over time.",
  },
  {
    q: "What ports need to be open?",
    a: "Agents communicate to WatchTower on port 50051 (TCP, gRPC). The web dashboard runs on port 5050 (TCP). OpenSearch API is internal on port 9200 and should not be exposed externally.",
  },
];

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const ref = useScrollReveal();

  return (
    <section
      id="faq"
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      style={{ background: "var(--surface)" }}
      aria-labelledby="faq-heading"
    >
      <div className="max-w-3xl mx-auto">
        <div className="text-center mb-16">
          <p
            className="text-xs font-mono uppercase tracking-widest mb-3"
            style={{ color: "var(--accent)" }}
          >
            FAQ
          </p>
          <h2
            id="faq-heading"
            className="text-4xl sm:text-5xl font-black tracking-tight text-balance"
            style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
          >
            Questions, answered.
          </h2>
        </div>

        <dl>
          {faqs.map((faq, i) => (
            <div key={i} className="faq-item">
              <dt>
                <button
                  className="faq-trigger"
                  onClick={() => setOpenIndex(openIndex === i ? null : i)}
                  aria-expanded={openIndex === i}
                  aria-controls={`faq-answer-${i}`}
                  id={`faq-question-${i}`}
                >
                  <span>{faq.q}</span>
                  <svg
                    className={`faq-icon ${openIndex === i ? "open" : ""}`}
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    aria-hidden="true"
                  >
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                </button>
              </dt>
              <dd
                id={`faq-answer-${i}`}
                role="region"
                aria-labelledby={`faq-question-${i}`}
                className={`faq-content ${openIndex === i ? "open" : ""}`}
              >
                {faq.a}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
