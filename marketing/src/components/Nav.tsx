"use client";

import { useEffect, useState } from "react";

const LionLogo = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 128 128"
    role="img"
    aria-label="CoreNest"
    className="size-8 shrink-0"
  >
    <defs>
      <linearGradient id="nav-g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#f6b73c" />
        <stop offset="100%" stopColor="#f08a24" />
      </linearGradient>
    </defs>
    <rect width="128" height="128" rx="20" fill="#111827" />
    <path
      d="M64 18 98 34v26c0 24-13 40-34 50C43 100 30 84 30 60V34l34-16z"
      fill="url(#nav-g)"
    />
    <path
      d="M64 35c-10 0-18 8-18 18 0 8 4 12 9 17 4 4 9 8 9 17 0-9 5-13 9-17 5-5 9-9 9-17 0-10-8-18-18-18z"
      fill="#111827"
    />
    <circle cx="64" cy="52" r="8" fill="#fef3c7" />
  </svg>
);

const SunIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="18"
    height="18"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
  </svg>
);

const MoonIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="18"
    height="18"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);

const navLinks = [
  { href: "#features", label: "Features" },
  { href: "#how-it-works", label: "How It Works" },
  { href: "#pricing", label: "Pricing" },
  { href: "#faq", label: "FAQ" },
];

export default function Nav() {
  const [isDark, setIsDark] = useState(true);
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const dark = saved ? saved === "dark" : prefersDark;
    setIsDark(dark);
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.classList.toggle("light", !dark);
  }, []);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && menuOpen) setMenuOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [menuOpen]);

  const toggleTheme = () => {
    const next = !isDark;
    setIsDark(next);
    document.documentElement.classList.toggle("dark", next);
    document.documentElement.classList.toggle("light", !next);
    localStorage.setItem("theme", next ? "dark" : "light");
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 nav-blur ${
        scrolled ? "border-b" : ""
      }`}
      style={{
        background: scrolled ? "rgba(13, 17, 23, 0.85)" : "transparent",
        borderColor: scrolled ? "var(--border)" : "transparent",
        paddingTop: "env(safe-area-inset-top)",
        paddingLeft: "env(safe-area-inset-left)",
        paddingRight: "env(safe-area-inset-right)",
      }}
    >
      <nav
        className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between"
        role="navigation"
        aria-label="Main navigation"
      >
        {/* Logo */}
        <a
          href="#"
          className="flex items-center gap-3 font-bold text-lg tracking-tight"
          style={{ color: "var(--text)" }}
          aria-label="CoreNest — go to top"
        >
          <LionLogo />
          <span aria-hidden="true">
            Sentinel{" "}
            <span style={{ color: "var(--accent)" }}>Core</span>
          </span>
        </a>

        {/* Desktop nav */}
        <ul className="hidden md:flex items-center gap-1" role="list">
          {navLinks.map((link) => (
            <li key={link.href}>
              <a
                href={link.href}
                className="underline-grow px-4 py-2 text-sm font-medium rounded-md transition-colors duration-200"
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

        {/* Right actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg transition-colors duration-200"
            style={{ color: "var(--muted)" }}
            aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
            onMouseEnter={(e) =>
              ((e.currentTarget as HTMLButtonElement).style.color =
                "var(--text)")
            }
            onMouseLeave={(e) =>
              ((e.currentTarget as HTMLButtonElement).style.color =
                "var(--muted)")
            }
          >
            {isDark ? <SunIcon /> : <MoonIcon />}
          </button>

          <a href="#pricing" className="btn-primary hidden md:inline-flex">
            Get Started
            <span className="btn-arrow" aria-hidden="true">→</span>
          </a>

          {/* Mobile hamburger */}
          <button
            className="md:hidden p-2 rounded-lg"
            style={{ color: "var(--muted)" }}
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
          >
            <svg
              width="20"
              height="20"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              {menuOpen ? (
                <>
                  <line x1="4" y1="4" x2="16" y2="16" />
                  <line x1="16" y1="4" x2="4" y2="16" />
                </>
              ) : (
                <>
                  <line x1="3" y1="6" x2="17" y2="6" />
                  <line x1="3" y1="12" x2="17" y2="12" />
                  <line x1="3" y1="18" x2="17" y2="18" />
                </>
              )}
            </svg>
          </button>
        </div>
      </nav>

      {/* Mobile menu */}
      {menuOpen && (
        <div
          id="mobile-menu"
          className="md:hidden border-t px-4 py-4 space-y-1 nav-blur"
          style={{
            background: "rgba(13, 17, 23, 0.95)",
            borderColor: "var(--border)",
          }}
        >
          {navLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="block px-4 py-3 rounded-lg text-sm font-medium"
              style={{ color: "var(--muted)" }}
              onClick={() => setMenuOpen(false)}
            >
              {link.label}
            </a>
          ))}
          <div className="pt-2">
            <a
              href="#pricing"
              className="btn-primary w-full justify-center"
              onClick={() => setMenuOpen(false)}
            >
              Get Started
              <span className="btn-arrow" aria-hidden="true">→</span>
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
