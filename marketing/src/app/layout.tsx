import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel Core SIEM — Enterprise Security, Zero Compromise",
  description:
    "Unified endpoint telemetry, real-time threat detection with Sigma rules, and compliance monitoring across your entire fleet. Open-source SIEM built for modern security teams.",
  keywords: [
    "SIEM",
    "security monitoring",
    "threat detection",
    "endpoint monitoring",
    "Sigma rules",
    "MITRE ATT&CK",
    "open source security",
    "compliance",
    "HIPAA",
  ],
  authors: [{ name: "Sentinel Core" }],
  openGraph: {
    title: "Sentinel Core SIEM",
    description:
      "Enterprise-grade security monitoring. Endpoint telemetry, Sigma rule detection, and compliance in one unified platform.",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "Sentinel Core SIEM",
    description: "Enterprise-grade security monitoring for modern teams.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
