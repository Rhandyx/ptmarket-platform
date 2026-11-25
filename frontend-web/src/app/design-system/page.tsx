import type { Metadata } from "next";
import { Showcase } from "../../components/ui/Showcase";

export const metadata: Metadata = {
  title: "Design system",
  robots: { index: false, follow: false },
};

export default function DesignSystemPage() {
  return <Showcase />;
}
