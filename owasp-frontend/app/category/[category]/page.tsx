"use client";

import { useParams } from "next/navigation";
import CategoryPage from "../../components/CategoryPage";

const CATEGORY_MAP: Record<string, string> = {
  A01: "A01: Broken Access Control",
  A02: "A02: Cryptographic Failures",
  A03: "A03: Injection",
  A04: "A04: Insecure Design",
  A05: "A05: Security Misconfiguration",
  A06: "A06: Vulnerable and Outdated Components",
  A07: "A07: Identification and Authentication Failures",
  A08: "A08: Software and Data Integrity Failures",
  A09: "A09: Security Logging and Monitoring Failures",
  A10: "A10: Server-Side Request Forgery (SSRF)",
};

export default function Page() {
  const params = useParams();
  const key = params.category as string;

  const categoryName = CATEGORY_MAP[key] ?? "Unknown OWASP Category";

  return <CategoryPage category={categoryName} />;
}
