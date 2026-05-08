"use client";

import { useScrollReveal } from "@/hooks/useScrollReveal";

const testimonials = [
  {
    quote:
      "We went from zero visibility to monitoring 60 Windows endpoints with full Sigma detection coverage in a single weekend. The automated deployment scripts made it painless.",
    author: "Marcus T.",
    role: "SOC Lead, Mid-Market Fintech",
    initials: "MT",
    color: "#58a6ff",
  },
  {
    quote:
      "The MITRE ATT&CK mapping on every alert means my analysts immediately understand the threat context. No more googling what a detection means in the middle of an incident.",
    author: "Priya S.",
    role: "Senior Security Engineer",
    initials: "PS",
    color: "#f6b73c",
  },
  {
    quote:
      "We evaluated Wazuh and Elastic Security. Sentinel Core was the only one that let us run community Sigma rules natively — no conversion pipeline, no maintenance overhead.",
    author: "Daniel K.",
    role: "Infrastructure Security, Healthcare SaaS",
    initials: "DK",
    color: "#3fb950",
  },
];

const StarIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="currentColor"
    className="w-4 h-4"
    aria-hidden="true"
  >
    <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25z" />
  </svg>
);

export default function Testimonials() {
  const ref = useScrollReveal();

  return (
    <section
      ref={ref}
      className="fade-section py-24 px-4 sm:px-6 lg:px-8"
      style={{ background: "var(--surface)" }}
      aria-labelledby="testimonials-heading"
    >
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <p
            className="text-xs font-mono uppercase tracking-widest mb-3"
            style={{ color: "var(--accent)" }}
          >
            From the field
          </p>
          <h2
            id="testimonials-heading"
            className="text-4xl sm:text-5xl font-black tracking-tight text-balance"
            style={{ letterSpacing: "-0.03em", color: "var(--text)" }}
          >
            Security teams love it.
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 stagger-children">
          {testimonials.map((t) => (
            <figure
              key={t.author}
              className="card-glow rounded-2xl p-8 flex flex-col gap-6"
              style={{
                background: "var(--bg)",
                border: "1px solid var(--border)",
              }}
            >
              <div
                className="flex gap-1"
                role="img"
                aria-label="5 star rating"
              >
                {Array.from({ length: 5 }).map((_, i) => (
                  <span key={i} style={{ color: t.color }}>
                    <StarIcon />
                  </span>
                ))}
              </div>
              <blockquote>
                <p
                  className="text-sm leading-relaxed text-pretty"
                  style={{ color: "var(--muted)" }}
                >
                  &ldquo;{t.quote}&rdquo;
                </p>
              </blockquote>
              <figcaption className="flex items-center gap-3 mt-auto">
                <div
                  className="size-10 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                  style={{
                    background: `${t.color}20`,
                    color: t.color,
                    border: `1px solid ${t.color}30`,
                  }}
                  aria-hidden="true"
                >
                  {t.initials}
                </div>
                <div>
                  <p
                    className="text-sm font-semibold"
                    style={{ color: "var(--text)" }}
                  >
                    {t.author}
                  </p>
                  <p className="text-xs" style={{ color: "var(--muted)" }}>
                    {t.role}
                  </p>
                </div>
              </figcaption>
            </figure>
          ))}
        </div>
      </div>
    </section>
  );
}
