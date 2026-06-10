/* eslint-disable */
// website.jsx — CoreNest marketing site
// One-file React app. Composes hero, trust strip, stats, features,
// product showcase, MITRE demo, threat ticker, comparison, quotes,
// pricing, final CTA, and footer.

const { useState: uS, useEffect: uE, useRef: uR } = React;

/* ── tiny icon helper (subset of product I, redrawn for marketing) ── */
const Ico = ({ d, children, size = 16, stroke = 1.6, fill = 'none' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill} stroke="currentColor"
       strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">
    {d && <path d={d}/>}{children}
  </svg>
);
const IC = {
  shield: <Ico><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></Ico>,
  arrow:  <Ico><path d="M5 12h14M13 6l6 6-6 6"/></Ico>,
  play:   <Ico fill="currentColor" stroke="none"><path d="M8 5v14l11-7z"/></Ico>,
  check:  <Ico><path d="M20 6 9 17l-5-5"/></Ico>,
  x:      <Ico><path d="M18 6 6 18M6 6l12 12"/></Ico>,
  star:   <Ico fill="currentColor" stroke="none"><path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z"/></Ico>,
  zap:    <Ico><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/></Ico>,
  cross:  <Ico><circle cx="12" cy="12" r="9"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/></Ico>,
  swirl:  <Ico><path d="M21 12a9 9 0 1 1-9-9c4.5 0 7 3 7 7s-2.5 5-5 5-3-1.5-3-3"/></Ico>,
  compass:<Ico><circle cx="12" cy="12" r="9"/><path d="m16 8-6 2-2 6 6-2 2-6z"/></Ico>,
  flask:  <Ico><path d="M9 3h6M10 3v6L4 20a2 2 0 0 0 1.7 3h12.6A2 2 0 0 0 20 20l-6-11V3"/></Ico>,
  cloud:  <Ico><path d="M17 19a5 5 0 0 0 .5-9.9 7 7 0 0 0-13.5 2.4A4 4 0 0 0 5 19h12z"/></Ico>,
  scale:  <Ico><path d="M12 3v18M6 7l-3 7c0 2 1.5 3 3 3s3-1 3-3L6 7zM18 7l-3 7c0 2 1.5 3 3 3s3-1 3-3l-3-7zM5 7h14"/></Ico>,
  chip:   <Ico><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/></Ico>,
  search: <Ico><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></Ico>,
  gauge:  <Ico><path d="M12 14 18 8M22 12a10 10 0 1 0-19.5 3"/><circle cx="12" cy="14" r="1.5"/></Ico>,
  ext:    <Ico><path d="M7 17 17 7M9 7h8v8"/></Ico>,
  twitter:<Ico stroke="none" fill="currentColor"><path d="M14 3h3l-7 8 8 10h-5.5l-4.5-6-5 6H0l7.5-8.5L0 3h5.5l4 5.5L14 3zm-1 16h1.5L6 5H4.5L13 19z"/></Ico>,
  github: <Ico stroke="none" fill="currentColor"><path d="M12 2C6.5 2 2 6.6 2 12.3c0 4.5 2.9 8.4 6.8 9.7.5.1.7-.2.7-.5v-1.8c-2.8.6-3.4-1.4-3.4-1.4-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.6-1.4-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.8 1 .8-.2 1.7-.3 2.5-.3s1.7.1 2.5.3c2-1.4 2.8-1 2.8-1 .6 1.5.2 2.5.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.3 4.7-4.6 4.9.4.3.7.9.7 1.8v2.7c0 .3.2.6.7.5 4-1.3 6.8-5.2 6.8-9.7C22 6.6 17.5 2 12 2z"/></Ico>,
  linkedin:<Ico stroke="none" fill="currentColor"><path d="M19 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zM8 18H5V9h3v9zM6.5 7.5a1.7 1.7 0 1 1 0-3.4 1.7 1.7 0 0 1 0 3.4zM18 18h-3v-4.4c0-1-.4-1.7-1.3-1.7-.7 0-1.1.5-1.3 1-.1.2-.1.4-.1.7V18h-3V9h3v1.3a3 3 0 0 1 2.7-1.5c2 0 3 1.3 3 3.7V18z"/></Ico>,
};

/* ── count-up hook ── */
function useCountUp(end, duration = 1600, trigger) {
  const [val, setVal] = uS(0);
  uE(() => {
    if (!trigger) return;
    let raf;
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setVal(end * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [trigger, end, duration]);
  return val;
}

/* ── reveal on scroll ── */
function useReveal() {
  uE(() => {
    const els = document.querySelectorAll('.reveal');
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('in');
          io.unobserve(e.target);
        }
      });
    }, { rootMargin: '-40px' });
    els.forEach(el => io.observe(el));
    return () => io.disconnect();
  }, []);
}

/* ── nav ── */
function Nav() {
  const [scrolled, setScrolled] = uS(false);
  uE(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);
  return (
    <nav className={`nav ${scrolled ? 'scrolled' : ''}`}>
      <div className="container nav-inner">
        <a className="nav-brand" href="#">
          <span className="nav-brand-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </span>
          CoreNest
        </a>
        <div className="nav-links">
          <a className="nav-link has-chevron" href="#features">Product</a>
          <a className="nav-link has-chevron" href="#showcase">Solutions</a>
          <a className="nav-link" href="#pricing">Pricing</a>
          <a className="nav-link" href="#">Customers</a>
          <a className="nav-link has-chevron" href="#">Resources</a>
          <a className="nav-link" href="#">Docs</a>
        </div>
        <div className="nav-actions">
          <a className="btn btn-ghost" href="#">Sign in</a>
          <a className="btn btn-primary" href="#cta">Book a demo {IC.arrow}</a>
        </div>
      </div>
    </nav>
  );
}

/* ── hero scope: animated dashboard preview ── */
function HeroScope() {
  const [phase, setPhase] = uS(0);
  uE(() => {
    const id = setInterval(() => setPhase(p => p + 1), 80);
    return () => clearInterval(id);
  }, []);

  const points = Array.from({ length: 36 }, (_, i) => {
    const t = (i + phase * 0.5) * 0.4;
    return 32 + Math.sin(t) * 16 + Math.sin(t * 2.3) * 8 + Math.cos(t * 1.7) * 6;
  });
  const W = 280, H = 80;
  const stepX = W / (points.length - 1);
  const path = points.map((v, i) => `${i === 0 ? 'M' : 'L'}${i * stepX},${H - v}`).join(' ');
  const area = `${path} L${W},${H} L0,${H} Z`;

  const feedRows = [
    { t: '16:42:08', s: 'crit', d: 'PowerShell encoded payload · prod-edge-04' },
    { t: '16:41:55', s: 'high', d: 'Brute-force on dc-east-01' },
    { t: '16:41:12', s: 'high', d: 'C2 beaconing · 185.220.101.7' },
    { t: '16:39:47', s: 'med',  d: 'Unusual login geo · jane.k' },
    { t: '16:38:21', s: 'med',  d: 'Scheduled task by SYSTEM' },
    { t: '16:37:03', s: 'low',  d: 'Outbound connection · web-fr-02' },
  ];

  return (
    <div className="hero-scope">
      <span className="hero-chip-float crit"><i/>+24 alerts in last 60s</span>
      <span className="hero-chip-float high"><i/>jane.k · risk 142</span>
      <span className="hero-chip-float ok"><i/>MTTR 18min</span>
      <span className="hero-chip-float med"><i/>MITRE T1059 +4</span>

      <div className="hero-scope-card">
        <div className="hero-scope-bar">
          <span className="dots"><i/><i/><i/></span>
          <span className="title">corenest / overview</span>
          <span className="live">LIVE</span>
        </div>
        <div className="hero-scope-body">
          <div className="hero-kpis">
            <div className="hero-kpi alerts">
              <div className="hero-kpi-l">Events 24h</div>
              <div className="hero-kpi-v">24,847</div>
            </div>
            <div className="hero-kpi crit">
              <div className="hero-kpi-l">Critical</div>
              <div className="hero-kpi-v crit">3</div>
            </div>
            <div className="hero-kpi agents">
              <div className="hero-kpi-l">Agents</div>
              <div className="hero-kpi-v">142<span style={{ fontSize: 12, color: 'var(--fg-4)' }}>/146</span></div>
            </div>
          </div>

          <div className="hero-trend">
            <div className="hero-trend-h">
              <h4>Alert volume · 24 h</h4>
              <span className="meta">peak 58 · 19:00 UTC</span>
            </div>
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 60, display: 'block' }}>
              <defs>
                <linearGradient id="heroGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35"/>
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity="0"/>
                </linearGradient>
              </defs>
              <path d={area} fill="url(#heroGrad)"/>
              <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.5"/>
            </svg>
          </div>

          <div className="hero-feed">
            <div className="hero-feed-h">
              <span className="live">LIVE FEED</span>
              <span style={{ marginLeft: 'auto' }}>{feedRows.length}+ alerts/min</span>
            </div>
            <div className="hero-feed-list">
              {[...feedRows, ...feedRows].map((r, i) => (
                <div className="row" key={i}>
                  <span className="t">{r.t}</span>
                  <span className={`sev ${r.s}`}/>
                  <span className="d">{r.d}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── hero section ── */
function Hero() {
  return (
    <section className="hero">
      <div className="hero-bg">
        <div className="hero-bg-grid"/>
        <div className="hero-bg-radar"/>
        <div className="hero-bg-glow"/>
      </div>
      <div className="container hero-inner">
        <div>
          <div className="eyebrow reveal">CoreNest v4.2 · now with AI triage</div>
          <h1 className="hero-title reveal" data-delay="1">
            Catch what<br/>
            <span className="strike">legacy SIEMs</span> <span className="accent">miss.</span>
          </h1>
          <p className="lede hero-sub reveal" data-delay="2">
            The SIEM built for modern SOCs. <b style={{ color: 'var(--fg)' }}>90% less alert fatigue</b>, an 18-minute average MTTR, and the only matrix view that actually maps to your detections.
          </p>
          <div className="hero-cta reveal" data-delay="3">
            <a className="btn btn-primary" href="#cta">Book a demo {IC.arrow}</a>
            <a className="btn btn-secondary" href="#showcase">{IC.play} Watch product tour</a>
          </div>
          <div className="hero-microstrip reveal" data-delay="4">
            <span>{IC.check} Free 14-day trial</span>
            <span>{IC.check} Deploy in under 30 minutes</span>
            <span>{IC.check} No credit card</span>
          </div>
        </div>
        <div className="reveal" data-delay="2">
          <HeroScope/>
        </div>
      </div>
    </section>
  );
}

/* ── trust strip (logo marquee) ── */
function Trust() {
  const logos = [
    { name: 'Northstar', icon: <Ico><polygon points="12,2 14,10 22,10 16,15 18,22 12,18 6,22 8,15 2,10 10,10"/></Ico> },
    { name: 'Vega Cloud', icon: <Ico><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3" fill="currentColor"/></Ico> },
    { name: 'Frontier Bank', icon: <Ico><rect x="3" y="10" width="18" height="10"/><polygon points="12,3 22,10 2,10"/></Ico> },
    { name: 'Acme Securities', icon: <Ico><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></Ico> },
    { name: 'Helix Health', icon: <Ico><path d="M4 20c4-4 12-4 16-16M4 4c4 4 12 4 16 16"/></Ico> },
    { name: 'Nexus Retail', icon: <Ico><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></Ico> },
    { name: 'Arctic Energy', icon: <Ico><polygon points="12,2 22,21 2,21"/></Ico> },
    { name: 'Lumen Labs', icon: <Ico><circle cx="12" cy="12" r="8"/><path d="m12 4v16M4 12h16"/></Ico> },
    { name: 'Quanta Telco', icon: <Ico><path d="M4 12a8 8 0 0 1 16 0M8 12a4 4 0 0 1 8 0"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/></Ico> },
  ];
  const stream = [...logos, ...logos];
  return (
    <section className="trust">
      <div className="trust-label reveal">Trusted by 700+ security teams worldwide</div>
      <div className="marquee">
        <div className="marquee-track">
          {stream.map((l, i) => (
            <span key={i} className="marquee-logo">{l.icon}{l.name}</span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── stats counter ── */
function Stats() {
  const ref = uR(null);
  const [vis, setVis] = uS(false);
  uE(() => {
    const io = new IntersectionObserver(([e]) => e.isIntersecting && setVis(true), { rootMargin: '-80px' });
    if (ref.current) io.observe(ref.current);
    return () => io.disconnect();
  }, []);

  const events  = useCountUp(4.2, 1400, vis);
  const mttr    = useCountUp(18,  1200, vis);
  const fatigue = useCountUp(90,  1500, vis);
  const packs   = useCountUp(142, 1300, vis);

  return (
    <section className="stats" ref={ref}>
      <div className="container">
        <div className="stats-grid">
          <div className="stat-item">
            <div className="v">{events.toFixed(1)}<span className="sub">B</span></div>
            <div className="l"><b>events ingested</b><br/>daily across our fleet</div>
          </div>
          <div className="stat-item">
            <div className="v">{Math.round(mttr)}<span className="sub">min</span></div>
            <div className="l"><b>average MTTR</b><br/>across customer SOCs</div>
          </div>
          <div className="stat-item">
            <div className="v">{Math.round(fatigue)}<span className="sub">%</span></div>
            <div className="l"><b>less alert noise</b><br/>via risk-based alerting</div>
          </div>
          <div className="stat-item">
            <div className="v">{Math.round(packs)}<span className="sub">+</span></div>
            <div className="l"><b>detection packs</b><br/>mapped to MITRE ATT&amp;CK</div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── features grid (9) ── */
function Features() {
  const items = [
    { icon: IC.zap,     title: 'Risk-based alerting',     body: 'Notables fire only when accumulated entity risk crosses your threshold. Triage what matters; auto-close the rest.' },
    { icon: IC.compass, title: 'MITRE ATT&CK coverage',   body: 'Every detection is mapped to a technique. Visualize coverage, find gaps, and tune detection content.' },
    { icon: IC.swirl,   title: 'UEBA out of the box',      body: 'Statistical baselines per identity, host, and service account. Anomalies surface without writing a single rule.' },
    { icon: IC.search,  title: 'KQL threat hunting',       body: 'Pivot through raw events with familiar Kibana-style query syntax. Save and share hunts across the team.' },
    { icon: IC.flask,   title: 'Detection Studio',         body: '700+ pre-built rules. Author your own with a live preview against historical data — no waiting to see if it fires.' },
    { icon: IC.cloud,   title: 'Cloud-native connectors',  body: 'AWS, Azure, GCP, Okta, Workspace, M365. One-click ingestion. Normalized to ECS so dashboards just work.' },
    { icon: IC.chip,    title: 'WatchNode agent',          body: 'Lightweight Linux / macOS / Windows agent. Sub-1% CPU footprint. Self-update, self-heal, signed binaries.' },
    { icon: IC.scale,   title: 'Compliance hub',           body: 'ISO 27001, NIST CSF, SOC 2, HIPAA, PCI-DSS, GDPR. Live posture scores; export-ready evidence packs.' },
    { icon: IC.gauge,   title: 'SOAR + playbooks',         body: '40+ pre-built response playbooks. Block IPs, isolate hosts, revoke sessions, page Pagerduty — without leaving the case.' },
  ];
  return (
    <section className="section" id="features">
      <div className="container">
        <div className="section-head reveal">
          <div className="eyebrow muted">What you get</div>
          <h2>One platform. Every<br/>capability your SOC needs.</h2>
          <p className="lede center" style={{ marginTop: 16 }}>
            From ingestion to investigation to response — CoreNest unifies the workflows you've stitched together for years.
          </p>
        </div>
        <div className="features-grid reveal" data-delay="1">
          {items.map((it, i) => (
            <article key={i} className="feature">
              <div className="feature-icon">{it.icon}</div>
              <h3>{it.title}</h3>
              <p>{it.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── product showcase: sticky scroll cycling through 4 demos ── */
function Showcase() {
  const [active, setActive] = uS(0);
  const items = [
    { name: 'Overview', desc: 'Operational pulse for the whole org. KPIs, severity breakdown, live alert feed.', demo: 'overview' },
    { name: 'Alerts & Incidents', desc: 'Triage queue with severity-banded KPIs, filter chips, and one-click investigation in Discover.', demo: 'alerts' },
    { name: 'MITRE ATT&CK matrix', desc: 'Coverage heatmap across all 12 enterprise tactics. Spot detection gaps at a glance.', demo: 'mitre' },
    { name: 'Risk-based alerting', desc: 'Accumulated entity scores with threshold-based notables. 90% less alert noise, by construction.', demo: 'risk' },
  ];

  const ref = uR(null);
  uE(() => {
    let id;
    const io = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        id = setInterval(() => setActive(a => (a + 1) % items.length), 4200);
      } else {
        clearInterval(id);
      }
    });
    if (ref.current) io.observe(ref.current);
    return () => { clearInterval(id); io.disconnect(); };
  }, []);

  return (
    <section className="section" id="showcase" ref={ref}>
      <div className="container">
        <div className="section-head reveal" style={{ textAlign: 'left', maxWidth: 700, marginBottom: 56 }}>
          <div className="eyebrow muted">The product</div>
          <h2>Built for the SOC analyst on shift,<br/>the hunter at 2&thinsp;AM, the director on Monday.</h2>
        </div>

        <div className="showcase-grid">
          <div className="showcase-rail reveal">
            {items.map((it, i) => (
              <div key={i}
                   className={`showcase-item ${active === i ? 'active' : ''}`}
                   onClick={() => setActive(i)}
                   onMouseEnter={() => setActive(i)}>
                <h3>{it.name}</h3>
                <p>{it.desc}</p>
              </div>
            ))}
            <div style={{ marginTop: 32 }}>
              <a className="btn btn-secondary" href="#cta">See full product tour {IC.arrow}</a>
            </div>
          </div>

          <div className="showcase-panel reveal" data-delay="1">
            <ShowcasePanel demo={items[active].demo}/>
          </div>
        </div>
      </div>
    </section>
  );
}

function ShowcasePanel({ demo }) {
  if (demo === 'overview')  return <DemoOverview/>;
  if (demo === 'alerts')    return <DemoAlerts/>;
  if (demo === 'mitre')     return <DemoMitre/>;
  if (demo === 'risk')      return <DemoRisk/>;
  return null;
}

function DemoFrame({ title, live, children }) {
  return (
    <div style={{ height: '100%' }}>
      <div className="hero-scope-bar">
        <span className="dots"><i/><i/><i/></span>
        <span className="title">corenest / {title}</span>
        {live && <span className="live">LIVE</span>}
      </div>
      <div style={{ padding: 20 }}>{children}</div>
    </div>
  );
}

function DemoOverview() {
  return (
    <DemoFrame title="overview" live>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
        {[
          { l: 'Events 24h', v: '24,847', c: 'var(--low)' },
          { l: 'Critical',   v: '3',      c: 'var(--crit)' },
          { l: 'Agents',     v: '142',    c: 'var(--ok)' },
          { l: 'Open cases', v: '7',      c: 'var(--accent)' },
        ].map((k, i) => (
          <div key={i} style={{
            background: 'var(--surface-2)', border: '1px solid var(--line)',
            borderRadius: 10, padding: 14, position: 'relative', overflow: 'hidden',
          }}>
            <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: 2, background: k.c }}/>
            <div style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>{k.l}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: 'var(--fg)' }}>{k.v}</div>
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--line)', borderRadius: 10, padding: '12px 16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 11 }}>
          <span style={{ color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Alert trend · 24h</span>
          <span style={{ color: 'var(--fg-4)', fontFamily: 'var(--font-mono)' }}>peak 58 · 19:00 UTC</span>
        </div>
        <TrendChart/>
      </div>
      <div style={{ marginTop: 14, background: 'var(--surface-2)', border: '1px solid var(--line)', borderRadius: 10, padding: 14 }}>
        <div style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: 10 }}>Live feed</div>
        {[
          { t: '16:42:08', s: 'crit', d: 'PowerShell encoded payload', a: 'prod-edge-04' },
          { t: '16:41:55', s: 'high', d: 'Brute-force on domain admin', a: 'dc-east-01' },
          { t: '16:41:12', s: 'high', d: 'Anomalous outbound to 185.220.101.7', a: 'prod-app-12' },
          { t: '16:39:47', s: 'med',  d: 'Unusual login geo · jane.k', a: 'web-fr-02' },
        ].map((r, i) => (
          <div key={i} style={{
            display: 'grid', gridTemplateColumns: '70px 14px 1fr 110px',
            gap: 10, alignItems: 'center', padding: '6px 0',
            fontSize: 11, borderTop: i ? '1px solid var(--line)' : 'none',
          }}>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-4)' }}>{r.t}</span>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: `var(--${r.s})`,
                           boxShadow: r.s === 'crit' ? '0 0 6px var(--crit)' : 'none' }}/>
            <span style={{ color: 'var(--fg)' }}>{r.d}</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-3)', textAlign: 'right' }}>{r.a}</span>
          </div>
        ))}
      </div>
    </DemoFrame>
  );
}

function DemoAlerts() {
  return (
    <DemoFrame title="alerts" live>
      <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
        {['Critical','High','Medium','Low'].map((s, i) => (
          <span key={i} style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            height: 24, padding: '0 10px', borderRadius: 6,
            background: i === 0 ? 'var(--accent-soft)' : 'var(--surface-2)',
            color: i === 0 ? 'var(--accent)' : 'var(--fg-2)',
            border: `1px solid ${i === 0 ? 'rgba(45,212,191,0.32)' : 'var(--line)'}`,
            fontSize: 11, fontWeight: 500,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: `var(--${['crit','high','med','low'][i]})` }}/>
            {s}
          </span>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
        {[
          { l: 'Total alerts', v: '712', tag: '+18%', c: 'var(--low)' },
          { l: 'Critical',     v: '3',   tag: 'ATTN', c: 'var(--crit)' },
          { l: 'High',         v: '28',  tag: '+9',   c: 'var(--high)' },
          { l: 'Medium',       v: '681', tag: 'OK',   c: 'var(--med)' },
        ].map((k, i) => (
          <div key={i} style={{
            background: 'var(--surface-2)', border: '1px solid var(--line)',
            borderRadius: 10, padding: 12, position: 'relative', overflow: 'hidden',
          }}>
            <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: 2, background: k.c }}/>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontSize: 9.5, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{k.l}</span>
              <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: k.c, background: 'var(--surface-3)', padding: '1px 5px', borderRadius: 3 }}>{k.tag}</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: i === 1 ? 'var(--crit)' : 'var(--fg)' }}>{k.v}</div>
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--line)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '70px 60px 1fr 80px',
          gap: 10, padding: '8px 14px', fontSize: 10, color: 'var(--fg-4)',
          textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
          background: 'var(--bg-soft)', borderBottom: '1px solid var(--line)',
        }}>
          <span>Time</span><span>Sev</span><span>Incident</span><span>Status</span>
        </div>
        {[
          { t: '16:42:08', s: 'crit', d: 'PowerShell ransomware staging · prod-edge-04', st: 'in-triage' },
          { t: '16:41:55', s: 'high', d: 'Brute-force on dc-east-01', st: 'investigating' },
          { t: '16:41:12', s: 'high', d: 'Anomalous outbound to 185.220.101.7', st: 'investigating' },
          { t: '16:39:47', s: 'med',  d: 'Unusual login geo · jane.k', st: 'acknowledged' },
        ].map((r, i) => (
          <div key={i} style={{
            display: 'grid', gridTemplateColumns: '70px 60px 1fr 80px',
            gap: 10, padding: '8px 14px', alignItems: 'center',
            fontSize: 11, borderTop: i ? '1px solid var(--line)' : 'none',
          }}>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-4)' }}>{r.t}</span>
            <span>
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                height: 16, padding: '0 6px', fontSize: 9, fontWeight: 600,
                textTransform: 'uppercase', borderRadius: 4,
                color: `var(--${r.s})`, background: `var(--${r.s}-soft)`,
                fontFamily: 'var(--font-mono)',
              }}>
                <span style={{ width: 4, height: 4, borderRadius: '50%', background: `var(--${r.s})` }}/>
                {r.s}
              </span>
            </span>
            <span style={{ color: 'var(--fg)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.d}</span>
            <span style={{ fontSize: 10, color: 'var(--fg-3)' }}>{r.st}</span>
          </div>
        ))}
      </div>
    </DemoFrame>
  );
}

function DemoMitre() {
  const [lit, setLit] = uS(0);
  uE(() => {
    const id = setInterval(() => setLit(l => l + 1), 90);
    return () => clearInterval(id);
  }, []);

  const tactics = ['Recon','Resource','Init Acc','Exec','Persist','Priv Esc','Def Evade','Cred Acc','Discover','Lateral','C2','Impact'];
  const cellPattern = [2,1,3,9,3,1,5,6,2,4,7,1];
  return (
    <DemoFrame title="mitre-attack" live>
      <div style={{ marginBottom: 10, display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--fg-3)' }}>
        <span style={{ textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Technique coverage · 24 h</span>
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{Math.min(lit, 96)} cells lit · 12/12 tactics</span>
      </div>
      <div className="matrix-demo">
        {tactics.map((t, ti) => {
          const count = cellPattern[ti];
          return (
            <div key={ti} className="col">
              <div className="col-h">{t}</div>
              {Array.from({ length: count }).map((_, ci) => {
                const idx = ti * 8 + ci;
                const isLit = idx < lit;
                const cls = !isLit ? '' :
                  count >= 7 ? 'lit-crit' :
                  count >= 4 ? 'lit-hot' :
                  count >= 2 ? 'lit-warm' : '';
                return <div key={ci} className={`cell ${cls}`}/>;
              })}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 12, display: 'flex', gap: 12, fontSize: 10, color: 'var(--fg-3)', justifyContent: 'center' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 12, height: 8, borderRadius: 2, background: 'rgba(242,85,85,0.58)' }}/> Critical (5+)
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 12, height: 8, borderRadius: 2, background: 'rgba(242,85,85,0.32)' }}/> Hot (3–4)
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 12, height: 8, borderRadius: 2, background: 'rgba(245,158,11,0.18)' }}/> Warm (1–2)
        </span>
      </div>
    </DemoFrame>
  );
}

function DemoRisk() {
  const entities = [
    { id: 'jane.k@corp',     score: 142, threshold: 100, badge: 'JK', color: '#fb7185' },
    { id: 'svc-deploy-prod', score: 118, threshold: 100, badge: 'SD', color: '#fbbf24' },
    { id: 'prod-edge-04',    score:  96, threshold: 100, badge: 'P4', color: '#60a5fa' },
    { id: 'admin.root',      score:  82, threshold: 100, badge: 'AR', color: '#a78bfa' },
    { id: 'dc-east-01',      score:  64, threshold: 100, badge: 'DC', color: '#34d399' },
    { id: 'web-fr-02',       score:  41, threshold: 100, badge: 'WF', color: '#22d3ee' },
  ];
  return (
    <DemoFrame title="risk-based-alerting" live>
      <div style={{ marginBottom: 14, display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--fg-3)' }}>
        <span style={{ textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>Entity risk leaderboard</span>
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--crit)' }}>2 notables · threshold 100</span>
      </div>
      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--line)', borderRadius: 10, overflow: 'hidden' }}>
        {entities.map((e, i) => {
          const pct = Math.min(180, (e.score / e.threshold) * 100);
          const overThreshold = e.score >= e.threshold;
          return (
            <div key={i} style={{
              display: 'grid', gridTemplateColumns: '22px 1fr 60px 1fr 50px',
              gap: 12, padding: '11px 14px', alignItems: 'center',
              fontSize: 11, borderTop: i ? '1px solid var(--line)' : 'none',
            }}>
              <span style={{
                width: 22, height: 22, borderRadius: 6,
                background: e.color, color: '#0a0a0c',
                display: 'grid', placeItems: 'center',
                fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
              }}>{e.badge}</span>
              <span style={{ color: 'var(--fg)', fontWeight: 500 }}>{e.id}</span>
              <span style={{
                fontFamily: 'var(--font-mono)', fontWeight: 500,
                color: overThreshold ? 'var(--crit)' : e.score >= 70 ? 'var(--high)' : 'var(--ok)',
              }}>{e.score}</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ position: 'relative', flex: 1, height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                  <span style={{
                    display: 'block', height: '100%',
                    width: `${Math.min(100, pct)}%`,
                    background: overThreshold ? 'linear-gradient(90deg, var(--high), var(--crit))' :
                                e.score >= 70 ? 'linear-gradient(90deg, var(--med), var(--high))' :
                                'linear-gradient(90deg, var(--ok), var(--med))',
                    borderRadius: 3,
                  }}/>
                </span>
                {overThreshold && (
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 600,
                    color: 'var(--crit)', background: 'var(--crit-soft)',
                    padding: '2px 5px', borderRadius: 3,
                  }}>NOTABLE</span>
                )}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--fg-4)', textAlign: 'right' }}>
                {Math.round((e.score / e.threshold) * 100)}%
              </span>
            </div>
          );
        })}
      </div>
      <div style={{
        marginTop: 12,
        background: 'rgba(56,189,248,0.06)',
        border: '1px solid rgba(56,189,248,0.18)',
        borderRadius: 8, padding: '10px 14px',
        fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.5,
      }}>
        Only 2 notable alerts fired today — instead of the 187 raw alerts these entities generated.
        That's how CoreNest cuts noise by 90%.
      </div>
    </DemoFrame>
  );
}

/* ── animated trend chart used in demo ── */
function TrendChart() {
  const [phase, setPhase] = uS(0);
  uE(() => {
    const id = setInterval(() => setPhase(p => p + 1), 100);
    return () => clearInterval(id);
  }, []);
  const data = Array.from({ length: 40 }, (_, i) => ({
    crit: Math.max(0, Math.sin((i + phase * 0.4) * 0.3) * 1 + 1),
    high: Math.max(0, Math.cos((i + phase * 0.3) * 0.2) * 3 + 3),
    med:  Math.max(0, Math.sin((i + phase * 0.5) * 0.15) * 6 + 7),
    low:  Math.max(0, Math.cos((i + phase * 0.2) * 0.1) * 10 + 12),
  }));
  const W = 540, H = 120;
  const max = Math.max(...data.map(d => d.crit + d.high + d.med + d.low)) || 1;
  const stepX = W / (data.length - 1);
  const series = [
    { key: 'low',  v: (d) => d.low + d.med + d.high + d.crit, color: 'var(--low)' },
    { key: 'med',  v: (d) => d.med + d.high + d.crit,         color: 'var(--med)' },
    { key: 'high', v: (d) => d.high + d.crit,                 color: 'var(--high)' },
    { key: 'crit', v: (d) => d.crit,                          color: 'var(--crit)' },
  ];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 110, display: 'block' }}>
      {series.map((s, si) => {
        const top = data.map((d, i) => `${i * stepX},${H - (s.v(d) / max) * H}`).join(' ');
        return (
          <polyline key={si} points={`${top} ${W},${H} 0,${H}`}
                    fill={s.color} fillOpacity="0.22" stroke={s.color} strokeWidth="1.2" strokeOpacity="0.85"/>
        );
      })}
    </svg>
  );
}

/* ── threat ticker ── */
function Ticker() {
  const items = [
    { s: 'crit', t: '16:42:08', d: 'PowerShell encoded payload', a: 'prod-edge-04' },
    { s: 'high', t: '16:41:55', d: 'Brute-force domain admin',   a: 'dc-east-01' },
    { s: 'high', t: '16:41:12', d: 'C2 beaconing to 185.220.101.7', a: 'prod-app-12' },
    { s: 'med',  t: '16:39:47', d: 'Unusual login geo · jane.k', a: 'web-fr-02' },
    { s: 'low',  t: '16:38:21', d: 'Scheduled task by SYSTEM',   a: 'jumpbox-prod' },
    { s: 'ok',   t: '16:37:03', d: 'Containment playbook succeeded · 2.3s', a: 'soar' },
    { s: 'crit', t: '16:36:18', d: 'IAM key exposure detected',  a: 'aws-cloudtrail' },
    { s: 'med',  t: '16:35:09', d: 'MITRE T1071 · app-layer C2', a: 'mail-relay-02' },
    { s: 'high', t: '16:34:42', d: 'Privilege escalation attempt', a: 'win-vdi-031' },
    { s: 'ok',   t: '16:33:55', d: 'UEBA model retrained · jane.k', a: 'ueba' },
  ];
  const stream = [...items, ...items];
  return (
    <section className="ticker">
      <div className="ticker-track">
        {stream.map((it, i) => (
          <span key={i} className="ticker-item">
            <span className={`sev ${it.s}`}/>
            <span className="t">{it.t}</span>
            <b>{it.d}</b>
            <span>· {it.a}</span>
          </span>
        ))}
      </div>
    </section>
  );
}

/* ── comparison ── */
function Compare() {
  const rows = [
    { f: 'Time to first alert',           us: 'under 30 min',     l: 'days–weeks',   d: 'weeks' },
    { f: 'Risk-based noise reduction',    us: '~90%',             l: 'not available', d: 'DIY' },
    { f: 'MITRE ATT&CK matrix view',      us: 'native, dynamic',  l: 'add-on',       d: 'manual' },
    { f: 'UEBA out of the box',           us: 'yes',              l: 'separate SKU', d: 'no' },
    { f: 'Cloud-native connectors',       us: '30+ pre-built',    l: 'limited',      d: 'roll your own' },
    { f: 'Total cost (mid-size SOC)',     us: '$2k–8k / mo',      l: '$30k+ / mo',   d: 'engineering time' },
    { f: 'Setup engineering',             us: '0.5 FTE',          l: '2–3 FTE',      d: '4+ FTE' },
  ];
  return (
    <section className="section" style={{ paddingTop: 80 }}>
      <div className="container">
        <div className="section-head reveal">
          <div className="eyebrow muted">Why teams switch</div>
          <h2>Compare to legacy SIEMs<br/>and DIY ELK stacks.</h2>
        </div>
        <div className="compare reveal" data-delay="1">
          <div className="compare-row head">
            <span>Capability</span>
            <span className="us">CoreNest</span>
            <span>Legacy SIEM</span>
            <span>DIY ELK</span>
          </div>
          {rows.map((r, i) => (
            <div key={i} className="compare-row">
              <span className="compare-feat">{r.f}</span>
              <span className="compare-cell us">{IC.check} {r.us}</span>
              <span className="compare-cell legacy">{IC.x} {r.l}</span>
              <span className="compare-cell diy">{IC.x} {r.d}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── testimonials ── */
function Testimonials() {
  const items = [
    {
      big: true,
      text: '"We replaced Splunk in 6 weeks. Our team went from drowning in 800 alerts a day to triaging 30 notables. We hired a hunter instead of another tier-1."',
      name: 'Maria Reyes', role: 'Director of SecOps · Frontier Bank', av: 'MR',
    },
    {
      text: '"The MITRE matrix view alone is worth the price. We finally see our coverage gaps without spreadsheets."',
      name: 'Alex Park', role: 'Threat Hunter · Vega Cloud', av: 'AP',
    },
    {
      text: '"Risk-based alerting is the killer feature. Our MTTR dropped from 4h to 22 minutes."',
      name: 'Liam Chen', role: 'SOC Manager · Northstar', av: 'LC',
    },
  ];
  return (
    <section className="section">
      <div className="container">
        <div className="section-head reveal">
          <div className="eyebrow muted">Customer love</div>
          <h2>Why analysts and directors<br/>both stay on the platform.</h2>
        </div>
        <div className="quotes-grid">
          {items.map((q, i) => (
            <div key={i} className={`quote ${q.big ? 'big' : ''} reveal`} data-delay={i + 1}>
              <span className="stars">
                {Array.from({ length: 5 }).map((_, j) => <span key={j}>{IC.star}</span>)}
              </span>
              <p className="quote-text">{q.text}</p>
              <div className="quote-by">
                <span className="quote-avatar">{q.av}</span>
                <span className="quote-meta">
                  <b>{q.name}</b>
                  <span>{q.role}</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── pricing ── */
function Pricing() {
  const plans = [
    {
      name: 'Starter',
      price: '$0',
      unit: 'free forever',
      tag: 'For small teams getting started with detection',
      cta: 'Start free',
      features: [
        '5 agents · 10 GB/mo ingestion',
        'Core SIEM + Discover + Alerts',
        'MITRE ATT&CK matrix',
        '7-day retention',
        'Community detection content',
      ],
    },
    {
      name: 'Business',
      price: '$2,400',
      unit: '/mo · billed annually',
      featured: true,
      tag: 'For growing SOCs that need risk-based alerting',
      cta: 'Start 14-day trial',
      features: [
        'Up to 500 agents · 500 GB/mo',
        <><b>Everything in Starter, plus:</b></>,
        'UEBA + Risk-based alerting',
        'SOAR with 40+ playbooks',
        '90-day retention · ECS normalized',
        'SSO + RBAC · 24×7 chat support',
      ],
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      unit: 'contact sales',
      tag: 'For regulated industries and global SOCs',
      cta: 'Talk to sales',
      features: [
        'Unlimited agents · custom retention',
        <><b>Everything in Business, plus:</b></>,
        'Air-gapped + multi-region',
        'Custom detection content packs',
        'Compliance hub (HIPAA, PCI, SOC 2)',
        'Dedicated CSM + named threat analyst',
      ],
    },
  ];
  return (
    <section className="section" id="pricing">
      <div className="container">
        <div className="section-head reveal">
          <div className="eyebrow muted">Pricing</div>
          <h2>Priced per ingestion, not per seat.<br/>No surprise overages.</h2>
          <p className="lede center" style={{ marginTop: 16 }}>
            14-day free trial on every plan. Cancel anytime. Migrate from Splunk and get a free quarter of credit.
          </p>
        </div>
        <div className="pricing-grid">
          {plans.map((p, i) => (
            <div key={i} className={`plan ${p.featured ? 'featured' : ''} reveal`} data-delay={i + 1}>
              {p.featured && <span className="plan-badge">Most popular</span>}
              <div className="plan-name">{p.name}</div>
              <div className="plan-price">{p.price}<span className="unit">{p.unit}</span></div>
              <div className="plan-tagline">{p.tag}</div>
              <a className={`btn ${p.featured ? 'btn-primary' : 'btn-secondary'} plan-cta`} href="#cta">
                {p.cta} {IC.arrow}
              </a>
              <ul className="plan-features">
                {p.features.map((f, j) => (
                  <li key={j}>{IC.check}<span>{f}</span></li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── final CTA ── */
function FinalCTA() {
  return (
    <section id="cta">
      <div className="container">
        <div className="finalcta reveal">
          <div className="finalcta-bg"/>
          <div className="finalcta-inner">
            <div className="eyebrow">Ready when you are</div>
            <h2>Stop triaging noise.<br/>Start hunting threats.</h2>
            <p className="lede" style={{ marginTop: 18 }}>
              See CoreNest running against your data in a 30-minute walkthrough. Or start a free trial and have your first alerts in under an hour.
            </p>
            <div className="ctas" style={{ marginTop: 32 }}>
              <a className="btn btn-primary" href="#">Book a demo {IC.arrow}</a>
              <a className="btn btn-secondary" href="#">Start free trial</a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── footer ── */
function Footer() {
  return (
    <footer className="foot">
      <div className="container">
        <div className="foot-grid">
          <div className="foot-brand">
            <a className="nav-brand" href="#">
              <span className="nav-brand-logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <path d="M9 12l2 2 4-4"/>
                </svg>
              </span>
              CoreNest
            </a>
            <p>Modern SIEM for modern SOCs. Cut alert noise by 90%, map every detection to MITRE, and respond in minutes — not hours.</p>
          </div>
          <div className="foot-col">
            <h5>Product</h5>
            <a href="#">Overview</a>
            <a href="#">Alerts</a>
            <a href="#">Threat Hunting</a>
            <a href="#">UEBA</a>
            <a href="#">MITRE ATT&amp;CK</a>
            <a href="#">Risk-based alerting</a>
          </div>
          <div className="foot-col">
            <h5>Solutions</h5>
            <a href="#">Mid-market SOCs</a>
            <a href="#">Enterprise</a>
            <a href="#">MSSPs</a>
            <a href="#">Compliance</a>
            <a href="#">Cloud security</a>
          </div>
          <div className="foot-col">
            <h5>Resources</h5>
            <a href="#">Documentation</a>
            <a href="#">Detection library</a>
            <a href="#">Blog</a>
            <a href="#">Customer stories</a>
            <a href="#">Status</a>
            <a href="#">Changelog</a>
          </div>
          <div className="foot-col">
            <h5>Company</h5>
            <a href="#">About</a>
            <a href="#">Careers</a>
            <a href="#">Security</a>
            <a href="#">Trust center</a>
            <a href="#">Contact</a>
          </div>
        </div>
        <div className="foot-bottom">
          <span>© 2026 CoreNest, Inc. SOC 2 Type II · ISO 27001 · GDPR</span>
          <div className="foot-socials">
            <a href="#" title="Twitter">{IC.twitter}</a>
            <a href="#" title="GitHub">{IC.github}</a>
            <a href="#" title="LinkedIn">{IC.linkedin}</a>
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ── App ── */
function Site() {
  useReveal();
  return (
    <>
      <Nav/>
      <Hero/>
      <Trust/>
      <Stats/>
      <Showcase/>
      <Features/>
      <Ticker/>
      <Compare/>
      <Testimonials/>
      <Pricing/>
      <FinalCTA/>
      <Footer/>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('site-root')).render(<Site/>);
