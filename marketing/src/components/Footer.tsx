"use client";

const LionLogo = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 128 128"
    role="img"
    aria-label="CoreNest"
    className="w-7 h-7 flex-shrink-0"
  >
    <defs>
      <linearGradient id="footer-g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#f6b73c" />
        <stop offset="100%" stopColor="#f08a24" />
      </linearGradient>
    </defs>
    <rect width="128" height="128" rx="20" fill="#111827" />
    <path
      d="M64 18 98 34v26c0 24-13 40-34 50C43 100 30 84 30 60V34l34-16z"
      fill="url(#footer-g)"
    />
    <path
      d="M64 35c-10 0-18 8-18 18 0 8 4 12 9 17 4 4 9 8 9 17 0-9 5-13 9-17 5-5 9-9 9-17 0-10-8-18-18-18z"
      fill="#111827"
    />
    <circle cx="64" cy="52" r="8" fill="#fef3c7" />
  </svg>
);

const footerLinks = [
  {
    heading: "Product",
    links: [
      { label: "Features", href: "#features" },
      { label: "How It Works", href: "#how-it-works" },
      { label: "Pricing", href: "#pricing" },
      { label: "FAQ", href: "#faq" },
    ],
  },
  {
    heading: "Components",
    links: [
      { label: "WatchNode Agent", href: "#" },
      { label: "WatchTower Manager", href: "#" },
      { label: "WatchVault Indexer", href: "#" },
      { label: "Core Dashboard", href: "#" },
    ],
  },
  {
    heading: "Resources",
    links: [
      { label: "Documentation", href: "#" },
      { label: "Deployment Guide", href: "#" },
      { label: "Sigma Rules", href: "#" },
      { label: "MITRE ATT&CK", href: "#" },
    ],
  },
  {
    heading: "Company",
    links: [
      { label: "About", href: "#" },
      { label: "Security", href: "#" },
      { label: "Contact", href: "mailto:ahmed.tahseen.khan@gmail.com" },
      { label: "GitHub", href: "#" },
    ],
  },
];

export default function Footer() {
  return (
    <footer
      className="border-t py-16 px-4 sm:px-6 lg:px-8"
      style={{ borderColor: "var(--border)", background: "var(--bg)" }}
      role="contentinfo"
    >
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-12 mb-12">
          {/* Brand */}
          <div className="md:col-span-1">
            <a
              href="#"
              className="flex items-center gap-3 font-bold text-base mb-4"
              style={{ color: "var(--text)" }}
              aria-label="CoreNest home"
            >
              <LionLogo />
              <span>
                Sentinel{" "}
                <span style={{ color: "var(--accent)" }}>Core</span>
              </span>
            </a>
            <p
              className="text-sm leading-relaxed"
              style={{ color: "var(--muted)" }}
            >
              Open-source SIEM for security teams who need real detection, not
              dashboards theater.
            </p>
          </div>

          {/* Links */}
          {footerLinks.map((col) => (
            <nav key={col.heading} aria-label={`${col.heading} links`}>
              <h3
                className="text-xs font-mono uppercase tracking-widest mb-4"
                style={{ color: "var(--muted)" }}
              >
                {col.heading}
              </h3>
              <ul className="space-y-3" role="list">
                {col.links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      className="underline-grow text-sm"
                      style={{ color: "var(--muted)" }}
                      onMouseEnter={(e) =>
                        ((e.currentTarget as HTMLAnchorElement).style.color =
                          "var(--text)")
                      }
                      onMouseLeave={(e) =>
                        ((e.currentTarget as HTMLAnchorElement).style.color =
                          "var(--muted)")
                      }
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </div>

        {/* Bottom bar */}
        <div
          className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-8 border-t text-xs"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          <p>
            © {new Date().getFullYear()} CoreNest. Open source under MIT
            License.
          </p>
          <div className="flex items-center gap-1 font-mono">
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: "#3fb950" }}
              aria-hidden="true"
            />
            <span>All systems operational</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
