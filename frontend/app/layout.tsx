import React from 'react';

export const metadata = {
  title: 'AEGIS-ZK (v5.2) — Created by Shishir Vats',
  description: 'Zero-Trust Cryptographic Execution Firewall & Parametric Underwriting for AI Agents',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, backgroundColor: '#020617' }}>{children}</body>
    </html>
  );
}
