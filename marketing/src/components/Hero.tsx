"use client";

import { motion, useReducedMotion } from "framer-motion";

const DashboardMockup = () => (
  <div
    className="relative w-full rounded-xl overflow-hidden"
    style={{
      border: "1px solid var(--border)",
      background: "var(--surface)",
      boxShadow:
        "0 0 0 1px rgba(88,166,255,0.1), 0 32px 80px rgba(0,0,0,0.5), 0 0 80px rgba(88,166,255,0.06)",
    }}
  >
    {/* Window chrome */}
    <div
      className="flex items-center gap-2 px-4 py-3 border-b"
      style={{ background: "var(--dark-surface, #161b22)", borderColor: "var(--border)" }}
    >
      <span className="size-3 rounded-full" style={{ background: "#f85149" }} aria-hidden="true" />
      <span className="size-3 rounded-full" style={{ background: "#d29922" }} aria-hidden="true" />
      <span className="size-3 rounded-full" style={{ background: "#3fb950" }} aria-hidden="true" />
      <div
        className="ml-4 flex-1 max-w-48 rounded px-3 py-1 text-xs font-mono"
        style={{ background: "var(--bg, #0d1117)", color: "var(--muted)", border: "1px solid var(--border)" }}
      >
        corenest.local:5050
      </div>
    </div>

    {/* Sidebar + main content */}
    <div className="flex" style={{ minHeight: "340px" }}>
      {/* Sidebar */}
      <div
        className="hidden sm:flex flex-col gap-1 p-3 w-44 shrink-0 border-r"
        style={{ background: "var(--bg, #0d1117)", borderColor: "var(--border)" }}
      >
        {[
          { label: "Overview", active: true, icon: "⬡" },
          { label: "Alerts", active: false, icon: "⚠" },
          { label: "Endpoints", active: false, icon: "◉" },
          { label: "MITRE ATT&CK", active: false, icon: "◈" },
          { label: "Compliance", active: false, icon: "✓" },
          { label: "Threat Hunt", active: false, icon: "⬭" },
        ].map((item) => (
          <div
            key={item.label}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium"
            style={{
              background: item.active ? "rgba(88,166,255,0.1)" : "transparent",
              color: item.active ? "var(--accent)" : "var(--muted)",
              borderLeft: item.active ? "2px solid var(--accent)" : "2px solid transparent",
            }}
            aria-hidden="true"
          >
            <span>{item.icon}</span>
            <span>{item.label}</span>
          </div>
        ))}
      </div>

      {/* Main dashboard area */}
      <div className="flex-1 p-4 space-y-3" aria-hidden="true">
        {/* KPI row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: "Events (24h)", value: "2.4M", delta: "+12%", color: "#58a6ff" },
            { label: "Critical Alerts", value: "7", delta: "−3", color: "#f85149" },
            { label: "Endpoints", value: "60", delta: "All healthy", color: "#3fb950" },
            { label: "Risk Score", value: "32", delta: "Low", color: "#d29922" },
          ].map((kpi) => (
            <div key={kpi.label} className="rounded-lg p-3" style={{ background: "var(--bg, #0d1117)", border: "1px solid var(--border)" }}>
              <p className="text-xs" style={{ color: "var(--muted)" }}>{kpi.label}</p>
              <p className="text-xl font-bold font-mono tabular-nums mt-1" style={{ color: kpi.color }}>
                {kpi.value}
              </p>
              <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>{kpi.delta}</p>
            </div>
          ))}
        </div>

        {/* Alert feed */}
        <div className="rounded-lg overflow-hidden" style={{ background: "var(--bg, #0d1117)", border: "1px solid var(--border)" }}>
          <div className="px-3 py-2 border-b text-xs font-semibold" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
            RECENT DETECTIONS
          </div>
          {[
            { rule: "Mimikatz LSASS Access", host: "WIN-SRV-04", sev: "CRITICAL", sevColor: "#f85149", time: "2m ago" },
            { rule: "PowerShell Encoded Command", host: "DESKTOP-19", sev: "HIGH", sevColor: "#d29922", time: "8m ago" },
            { rule: "Suspicious Scheduled Task", host: "WIN-SRV-01", sev: "MEDIUM", sevColor: "#58a6ff", time: "14m ago" },
          ].map((alert) => (
            <div
              key={alert.rule}
              className="flex items-center justify-between px-3 py-2 border-b last:border-0 text-xs"
              style={{ borderColor: "var(--border)" }}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="size-1.5 rounded-full shrink-0" style={{ background: alert.sevColor }} />
                <span className="font-medium truncate" style={{ color: "var(--text, #e6edf3)" }}>{alert.rule}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-2">
                <span className="font-mono hidden sm:inline" style={{ color: "var(--muted)" }}>{alert.host}</span>
                <span className="px-1.5 py-0.5 rounded text-xs font-bold" style={{ color: alert.sevColor, background: `${alert.sevColor}18` }}>
                  {alert.sev}
                </span>
                <span className="tabular-nums" style={{ color: "var(--muted)" }}>{alert.time}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Mini chart */}
        <div className="rounded-lg p-3" style={{ background: "var(--bg, #0d1117)", border: "1px solid var(--border)" }}>
          <p className="text-xs font-semibold mb-2" style={{ color: "var(--muted)" }}>EVENT VOLUME — LAST 24H</p>
          <div className="flex items-end gap-0.5 h-12" aria-hidden="true">
            {[4, 7, 5, 9, 6, 11, 8, 14, 10, 8, 13, 16, 12, 18, 14, 20, 15, 22, 17, 19, 21, 16, 13, 10].map((h, i) => (
              <div
                key={i}
                className="flex-1 rounded-sm"
                style={{ height: `${(h / 22) * 100}%`, background: i === 23 ? "var(--accent)" : "rgba(88,166,255,0.25)" }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  </div>
);

const fadeUp = (delay: number) => ({
  hidden: { opacity: 0, y: 28 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: "easeOut", delay } },
});


export default function Hero() {
  const shouldReduceMotion = useReducedMotion();

  const variants = shouldReduceMotion
    ? { hidden: {}, visible: {} }
    : undefined;

  return (
    <section
      className="hero-mesh noise relative min-h-dvh flex flex-col items-center justify-center pt-20 pb-16 px-4 sm:px-6 lg:px-8 overflow-hidden"
      aria-label="Hero section"
    >
      {/* Decorative orbs — static, no animation, pure CSS radial gradients */}
      <div
        className="absolute top-1/4 left-1/2 -translate-x-1/2 size-[600px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(88,166,255,0.07) 0%, transparent 70%)", filter: "blur(40px)" }}
        aria-hidden="true"
      />
      <div
        className="absolute bottom-0 right-0 size-96 rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(246,183,60,0.05) 0%, transparent 70%)", filter: "blur(60px)" }}
        aria-hidden="true"
      />

      <div className="relative z-10 max-w-6xl mx-auto text-center">
        {/* Badge */}
        <motion.div
          className="inline-flex items-center gap-2 mb-8"
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0)}
        >
          <span
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold font-mono border"
            style={{ background: "rgba(88,166,255,0.08)", borderColor: "rgba(88,166,255,0.25)", color: "var(--accent)" }}
          >
            <span className="size-1.5 rounded-full animate-pulse" style={{ background: "#3fb950" }} aria-hidden="true" />
            Open Source · Production Ready · v1.0
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          className="text-5xl sm:text-6xl lg:text-7xl xl:text-8xl font-black leading-none mb-6 text-balance"
          style={{ letterSpacing: "-0.04em" }}
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0.12)}
        >
          <span style={{ color: "var(--text)" }}>Enterprise Security.</span>
          <br />
          <span className="gradient-text">Zero Compromise.</span>
        </motion.h1>

        {/* Subheadline */}
        <motion.p
          className="text-lg sm:text-xl lg:text-2xl max-w-3xl mx-auto mb-10 leading-relaxed text-pretty font-normal"
          style={{ color: "var(--muted)" }}
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0.24)}
        >
          CoreNest SIEM unifies endpoint telemetry, Sigma-rule threat
          detection, and compliance monitoring — across every machine in your
          fleet. Built for teams who can&apos;t afford to miss anything.
        </motion.p>

        {/* CTAs */}
        <motion.div
          className="flex flex-wrap items-center justify-center gap-4 mb-16"
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0.36)}
        >
          <a href="#pricing" className="btn-primary text-base px-6 py-3">
            Deploy Free
            <span className="btn-arrow" aria-hidden="true">→</span>
          </a>
          <a href="#how-it-works" className="btn-secondary text-base px-6 py-3">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="2" />
              <polygon points="10 8 16 12 10 16 10 8" />
            </svg>
            See How It Works
          </a>
        </motion.div>

        {/* Stats */}
        <motion.div
          className="flex flex-wrap justify-center gap-8 mb-16 text-sm"
          style={{ color: "var(--muted)" }}
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0.48)}
        >
          {[
            { value: "60+", label: "Endpoints Monitored" },
            { value: "2.4M", label: "Events / Day" },
            { value: "200+", label: "Sigma Rules" },
            { value: "100%", label: "Open Source" },
          ].map((stat) => (
            <div key={stat.label} className="flex flex-col items-center gap-1">
              <span className="text-2xl font-black font-mono tabular-nums" style={{ color: "var(--text)" }}>
                {stat.value}
              </span>
              <span className="text-xs uppercase">{stat.label}</span>
            </div>
          ))}
        </motion.div>

        {/* Product mockup */}
        <motion.div
          className="max-w-5xl mx-auto"
          initial="hidden"
          animate="visible"
          variants={variants ?? fadeUp(0.6)}
        >
          <DashboardMockup />
        </motion.div>
      </div>
    </section>
  );
}
