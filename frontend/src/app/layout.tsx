import type { Metadata } from "next";
import { AppShell } from "@/components/shell/app-shell";
import { getSentinelDataSource } from "@/data/data-source";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "SentinelAI Operations", template: "%s · SentinelAI" },
  description: "Behavioral threat operations console",
};
export const dynamic = "force-dynamic";

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const system = await getSentinelDataSource().getSystemStatus();
  return (
    <html lang="en">
      <body><AppShell system={system}>{children}</AppShell></body>
    </html>
  );
}
