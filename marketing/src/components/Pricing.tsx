"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const plans = [
  {
    name: "Community",
    price: "Free",
    period: "forever",
    description:
      "Full platform, self-hosted. Everything you need to get started.",
    cta: "Deploy Now",
    ctaHref: "#",
    featured: false,
    features: [
      "Unlimited endpoints",
      "WatchNode agent (Go)",
      "WatchTower rule engine",
      "WatchVault indexer",
      "200+ Sigma rules",
      "OpenSearch integration",
      "MITRE ATT&CK mapping",
      "Community support",
    ],
  },
  {
    name: "Team",
    price: "$0",
    period: "open source",
    description:
      "Add team workflows, extended retention, and priority rule updates.",
    cta: "Get Early Access",
    ctaHref: "#",
    featured: true,
    badge: "Most Popular",
    features: [
      "Everything in Community",
      "Multi-team dashboards",
      "180-day retention",
      "Threat intel feed updates",
      "Active response playbooks",
      "HIPAA compliance reports",
      "Role-based access control",
      "Priority issue support",
    ],
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "contact us",
    description:
      "Dedicated support, custom integrations, and SLA-backed deployments.",
    cta: "Contact Sales",
    ctaHref: "mailto:ahmed.tahseen.khan@gmail.com",
    featured: false,
    features: [
      "Everything in Team",
      "Custom Sigma rule development",
      "On-site / air-gapped deployment",
      "Custom integrations (SOAR, ticketing)",
      "Dedicated security engineer",
      "99.9% uptime SLA",
      "Audit log export",
      "Annual security review",
    ],
  },
];

const CheckIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className="w-4 h-4 flex-shrink-0"
    aria-hidden="true"
  >
    <polyline points="3 8 6 11 13 5" />
  </svg>
);

export default function Pricing() {
  const ref = useScrollReveal();

  return (
    <section
      id="pricing"
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      aria-labelledby="pricing-heading"
    >
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <p
            className="text-xs font-mono uppercase tracking-widest mb-3"
            style={{ color: "var(--accent)" }}
          >
            Pricing
          </p>
          <h2
            id="pricing-heading"
            className="text-4xl sm:text-5xl font-black tracking-tight mb-4 text-balance"
            style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
          >
            Simple, transparent pricing.
          </h2>
          <p className="text-base text-pretty" style={{ color: "var(--muted)" }}>
            The full platform is free and open source. Paid tiers add team
            features and enterprise support.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 stagger-children">
          {plans.map((plan) => (
            <div
              key={plan.name}
              className={`relative rounded-2xl p-8 flex flex-col gap-6 ${
                plan.featured ? "pricing-featured" : ""
              }`}
              style={{
                background: plan.featured ? "var(--surface)" : "var(--bg)",
                border: `1px solid ${plan.featured ? "var(--accent)" : "var(--border)"}`,
              }}
            >
              {plan.badge && (
                <div
                  className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 py-1 rounded-full text-xs font-bold"
                  style={{
                    background: "var(--accent)",
                    color: "var(--bg)",
                  }}
                >
                  {plan.badge}
                </div>
              )}

              <div>
                <h3
                  className="text-sm font-mono uppercase tracking-widest mb-2"
                  style={{ color: "var(--muted)" }}
                >
                  {plan.name}
                </h3>
                <div className="flex items-baseline gap-2 mb-2">
                  <span
                    className="text-4xl font-black tabular-nums"
                    style={{ color: "var(--text)", letterSpacing: "-0.03em" }}
                  >
                    {plan.price}
                  </span>
                  <span className="text-sm" style={{ color: "var(--muted)" }}>
                    {plan.period}
                  </span>
                </div>
                <p className="text-sm leading-relaxed text-pretty" style={{ color: "var(--muted)" }}>
                  {plan.description}
                </p>
              </div>

              <a
                href={plan.ctaHref}
                className={plan.featured ? "btn-primary justify-center" : "btn-secondary justify-center"}
              >
                {plan.cta}
                {plan.featured && (
                  <span className="btn-arrow" aria-hidden="true">→</span>
                )}
              </a>

              <ul className="space-y-3" role="list">
                {plan.features.map((feature) => (
                  <li
                    key={feature}
                    className="flex items-center gap-3 text-sm"
                    style={{ color: "var(--muted)" }}
                  >
                    <span style={{ color: "#3fb950" }}>
                      <CheckIcon />
                    </span>
                    {feature}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
