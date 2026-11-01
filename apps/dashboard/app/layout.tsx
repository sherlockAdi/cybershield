import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = { title: 'ServerGuard AI | Security Control Plane', description: 'Secure access, organizations and server operations in one control plane.' };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
