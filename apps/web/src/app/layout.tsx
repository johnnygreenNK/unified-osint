import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "UnifiedOSINT",
  description: "Panel wyszukiwania OSINT",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pl">
      <body>{children}</body>
    </html>
  );
}
