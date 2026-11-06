"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

export function FindingAssurancePanel({ finding, contextTask }: { finding: Finding; contextTask?: string }) {
  const [counts, setCounts] = React.useState<{ captures: number; reproduced: number; fixed: number }>();
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    let current = true;
    setError("");
    setCounts(undefined);
    Promise.all([api.findingTraffic(finding.id, contextTask), api.findingRetests(finding.id)])
      .then(([traffic, retests]) => {
        if (!current) return;
        const completed = retests.filter((r) => r.status === "completed");
        setCounts({
          captures: new Set(traffic.bindings.map((b) => b.snapshot.source_traffic_id)).size,
          reproduced: completed.filter((r) => r.verdict === "reproduced").length,
          fixed: completed.filter((r) => r.verdict === "fixed").length,
        });
      })
      .catch(() => { if (current) setError("Could not load evidence records."); });
    return () => { current = false; };
  }, [finding, contextTask]);

  async function download() {
    setBusy(true);
    setError("");
    try {
      await api.exportFindings({ scope: "selected", format: "md-zip", ids: [finding.id] });
    } catch {
      setError("Evidence export failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Evidence verification</CardTitle></CardHeader>
      <CardContent className="space-y-3 text-sm">
        {counts && <p>Distinct captures: {counts.captures}. Completed retests reporting reproduction: {counts.reproduced}. Reporting a fix: {counts.fixed}.</p>}
        {counts && counts.fixed > 0 && counts.reproduced > 0 && <p>Retest verdicts differ. Compare revisions and capture times.</p>}
        <p>Export the original captures for offline comparison with an independent collection and a known-good control.</p>
        <Button variant="outline" size="sm" disabled={busy || !counts?.captures} onClick={download}>
          {busy ? "Exporting…" : "Download evidence ZIP"}
        </Button>
        {error && <p role="alert">{error}</p>}
      </CardContent>
    </Card>
  );
}
