import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";

interface ToolCallRecord {
  decision?: string;
  id: string;
  metadata: Record<string, unknown>;
  status: string;
  toolName: string;
}

interface ApprovalRecord {
  id: string;
  toolCallId: string;
}

interface AuditRecord {
  toolCallId?: string;
  type: string;
}

interface ExecutionAttemptRecord {
  state: string;
}

test.beforeEach(async ({ page }) => {
  await clearDemoState(page);
});

test("community console exposes only OSS surfaces", async ({ page }) => {
  await expectCommunityRouteMissing(page, "/v1/system/capabilities");
  await expectCommunityRouteMissing(page, "/v1/agents/templates");

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "AI tool-call approval gateway" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Run the lifecycle" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Connect an agent or host" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Harden self-hosting" }),
  ).toBeVisible();

  const nav = page.getByRole("navigation", { name: "Admin view" });
  await expect(nav.getByRole("link")).toHaveCount(7);
  await expect(nav.getByRole("link", { name: /^Overview/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Audit/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Approvals/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Runner queue/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Policy/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Integrations/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Demo lab/ })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^Agents/ })).toHaveCount(0);
  await expect(page.getByText(/control plane/i)).toHaveCount(0);

  await page.goto("/app#/integrations");
  await expect(
    page.getByRole("heading", { name: "Approval channels" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Local mock demo tools" }),
  ).toBeVisible();
  const developerSources = page.locator(".developer-sources-section");
  await expect(developerSources).not.toHaveAttribute("open", "");
  await expect(
    developerSources.locator(".integration-disclosure-content"),
  ).toBeHidden();
  await developerSources.locator("summary").click();
  await expect(developerSources).toHaveAttribute("open", "");
  await expect(
    developerSources.locator(".integration-disclosure-content"),
  ).toBeVisible();

  await page.goto("/app#/agents");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.goto("/app#/demo");
  const tunnelPanel = page.locator(".chatgpt-tunnel-panel");
  await expect(
    tunnelPanel.getByRole("heading", { name: "Connect ChatGPT" }),
  ).toBeVisible();
  await expect(tunnelPanel.getByText("Waiting for first call")).toBeVisible();
  await expect(tunnelPanel.getByLabel("OpenAI tunnel ID")).toBeVisible();
  await expect
    .poll(() =>
      tunnelPanel.evaluate(
        (element) => element.scrollWidth <= element.clientWidth,
      ),
    )
    .toBe(true);
  await expect(
    page.getByRole("heading", { name: "Manual MCP action catalog" }),
  ).toHaveCount(0);
  const guidedDemo = page.getByRole("heading", { name: "Agent demo" });
  await expect(guidedDemo).toBeVisible();
  expect(
    await guidedDemo.evaluate(
      (element, tunnel) =>
        Boolean(
          element.compareDocumentPosition(tunnel as Node) &
          Node.DOCUMENT_POSITION_FOLLOWING,
        ),
      await tunnelPanel
        .getByRole("heading", { name: "Connect ChatGPT" })
        .elementHandle(),
    ),
  ).toBe(true);

  const tunnelId = "tunnel_browsercheck123";
  await tunnelPanel.getByLabel("OpenAI tunnel ID").fill(tunnelId);
  await expect(tunnelPanel.locator(".chatgpt-tunnel-command")).toContainText(
    tunnelId,
  );
  await expect(
    tunnelPanel.locator(".chatgpt-tunnel-command"),
  ).not.toContainText(/runtime[-_ ]key/i);
  const tunnelSafety = await page.evaluate(() => ({
    dom: document.documentElement.innerHTML,
    storage: JSON.stringify({
      local: { ...window.localStorage },
      session: { ...window.sessionStorage },
    }),
  }));
  expect(tunnelSafety.dom).not.toContain("ACTIONPROXY_TUNNEL_RUNTIME_KEY");
  expect(tunnelSafety.dom).not.toContain("aprt_browser_secret_canary");
  expect(tunnelSafety.storage).not.toContain(tunnelId);
  expect(tunnelSafety.storage).not.toContain("runtime");
  expect(tunnelSafety.storage).not.toContain("aprt_browser_secret_canary");
});

test("community demo gates approval decisions and records audit evidence", async ({
  page,
}) => {
  await page.goto("/app#/");
  const existingToolCallIds = new Set(
    (await fetchToolCalls(page)).map((toolCall) => toolCall.id),
  );

  await page.goto("/app#/demo");
  const agentDemo = page.locator(".agent-demo-panel");
  await agentDemo.getByRole("button", { name: "Run full demo" }).click();
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Search support policy" }),
    "Complete",
  );
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Propose customer email" }),
    "Needs approval",
  );
  await expect(
    agentDemo.getByText("Paused as designed—no email was sent."),
  ).toBeVisible();
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Attempt unsafe customer deletion" }),
    "Ready",
  );

  const created = await waitForNewDemoEmailApproval(page, existingToolCallIds);
  await expect(
    agentDemo.getByRole("link", { name: "Review this approval" }),
  ).toHaveAttribute("href", `#/approvals/${created.approval.id}`);
  const storedProgress = await page.evaluate(() =>
    window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
  );
  expect(storedProgress).not.toContain("response");
  expect(storedProgress).not.toContain("result");
  expect(storedProgress).not.toContain("customer@example.com");

  expect(await fetchExecutionAttempts(page, created.toolCall.id)).toEqual([]);
  const preApprovalEventTypes = (
    await fetchAuditEvents(page, created.toolCall.id)
  ).map((event) => event.type);
  expect(preApprovalEventTypes).not.toContain("execution.attempt_dispatched");
  expect(preApprovalEventTypes).not.toContain("execution.attempt_completed");
  expect(preApprovalEventTypes).not.toContain("receipt.created");
  expect(preApprovalEventTypes).not.toContain("tool_call.executed");

  await page.goto(`/app#/approvals/${created.approval.id}`);
  await expect(
    page.getByRole("heading", { name: "Approval detail" }),
  ).toBeVisible();
  await expect(page.locator(".approval-detail .status-badge")).toHaveText(
    "pending",
  );
  await expect(
    page.getByRole("heading", { name: "Approval input comparison" }),
  ).toBeVisible();
  await expect(
    page.getByText(/"to": "customer@example.com"/).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect
    .poll(async () => (await fetchToolCall(page, created.toolCall.id)).status)
    .toBe("executed");
  await expect
    .poll(
      async () =>
        (await fetchExecutionAttempts(page, created.toolCall.id)).length,
    )
    .toBe(1);
  const attempts = await fetchExecutionAttempts(page, created.toolCall.id);
  expect(attempts).toHaveLength(1);
  expect(attempts[0]?.state).toBe("succeeded");
  const postApprovalEvents = await fetchAuditEvents(page, created.toolCall.id);
  for (const eventType of [
    "execution.attempt_dispatched",
    "execution.attempt_completed",
    "receipt.created",
    "tool_call.executed",
  ]) {
    expect(
      postApprovalEvents.filter((event) => event.type === eventType),
      eventType,
    ).toHaveLength(1);
  }

  await page.goto("/app#/demo");
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Propose customer email" }),
    "Complete",
  );
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Attempt unsafe customer deletion" }),
    "Blocked",
  );

  const denied = await waitForNewDemoToolCall(
    page,
    existingToolCallIds,
    "dangerous.delete_customer",
    "delete-customer",
  );
  expect(denied).toMatchObject({
    decision: "deny",
    status: "blocked",
    toolName: "dangerous.delete_customer",
  });

  await page.goto("/app#/audit");
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();

  await page.getByLabel("Audit search").fill(created.toolCall.id);
  const approvedAuditGroup = page
    .locator(".audit-group")
    .filter({ hasText: created.toolCall.id })
    .first();
  await expandAuditGroup(approvedAuditGroup);
  await expect(
    approvedAuditGroup
      .locator(".timeline-event summary")
      .filter({ hasText: "approval.approved" })
      .first(),
  ).toBeVisible();
  await expect(
    approvedAuditGroup
      .locator(".timeline-event summary")
      .filter({ hasText: "receipt.created" })
      .first(),
  ).toBeVisible();
  await expect(
    approvedAuditGroup
      .locator(".timeline-event summary")
      .filter({ hasText: "tool_call.executed" })
      .first(),
  ).toBeVisible();

  await page.getByLabel("Audit search").fill(denied.id);
  const deniedAuditGroup = page
    .locator(".audit-group")
    .filter({ hasText: denied.id })
    .first();
  await expandAuditGroup(deniedAuditGroup);
  await expect(
    deniedAuditGroup
      .locator(".timeline-event summary")
      .filter({ hasText: "policy.deny" })
      .first(),
  ).toBeVisible();
});

test("pending approval survives reload and can be rejected without an email effect", async ({
  page,
}) => {
  const existingToolCallIds = new Set(
    (await fetchToolCalls(page)).map((toolCall) => toolCall.id),
  );
  await page.goto("/app#/demo");
  const agentDemo = page.locator(".agent-demo-panel");
  await agentDemo.getByRole("button", { name: "Run full demo" }).click();
  const created = await waitForNewDemoEmailApproval(page, existingToolCallIds);

  await page.reload();
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Propose customer email" }),
    "Needs approval",
  );
  await expect(
    agentDemo.getByText("Paused as designed—no email was sent."),
  ).toBeVisible();

  await page.goto(`/app#/approvals/${created.approval.id}`);
  await page
    .getByLabel("Rejection reason")
    .fill("Intentional Community rejection-path test.");
  await page.getByRole("button", { name: "Reject" }).click();
  await expect
    .poll(async () => (await fetchToolCall(page, created.toolCall.id)).status)
    .toBe("rejected");

  await page.goto("/app#/demo");
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Propose customer email" }),
    "Rejected",
  );
  await expectStatus(
    agentDemo
      .locator(".agent-step")
      .filter({ hasText: "Attempt unsafe customer deletion" }),
    "Blocked",
  );
});

test("API failure can be retried and empty gateway states stay actionable", async ({
  page,
}) => {
  let failToolCallsOnce = true;
  await page.route(/\/v1\/tool-calls\?limit=100$/u, async (route) => {
    if (failToolCallsOnce) {
      failToolCallsOnce = false;
      await route.fulfill({
        contentType: "application/json",
        json: { message: "Temporary browser-test outage." },
        status: 503,
      });
      return;
    }
    await route.continue();
  });

  await page.goto("/app#/");
  await expect(page.getByRole("alert")).toContainText(
    "Temporary browser-test outage.",
  );
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.locator(".snapshot-banner.recovered")).toContainText(
    "Gateway connection restored",
  );
  await expect(page.getByText("Local server online")).toBeVisible();

  failToolCallsOnce = true;
  await page.getByRole("button", { name: "Refresh gateway data" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Showing the last successful gateway snapshot",
  );
  await expect(page.getByRole("alert")).toContainText(
    "Temporary browser-test outage.",
  );
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.locator(".snapshot-banner.recovered")).toContainText(
    "Gateway connection restored",
  );

  await page.unroute(/\/v1\/tool-calls\?limit=100$/u);
  await page.route(/\/v1\/tool-calls\?limit=100$/u, (route) =>
    route.fulfill({ json: { toolCalls: [] } }),
  );
  await page.route(/\/v1\/approvals\/pending$/u, (route) =>
    route.fulfill({ json: { approvals: [] } }),
  );
  await page.route(/\/v1\/audit\?limit=500$/u, (route) =>
    route.fulfill({ json: { events: [] } }),
  );
  await page.route(/\/v1\/authorized-actions\?.*$/u, (route) =>
    route.fulfill({ json: { authorizedActions: [] } }),
  );
  await page.getByRole("button", { name: "Refresh gateway data" }).click();
  await expect(page.getByText("No tool calls yet")).toBeVisible();

  await page.goto("/app#/approvals");
  await expect(page.getByText("No approvals waiting")).toBeVisible();
  await page.goto("/app#/authorized");
  await expect(page.getByText("No runner grants")).toBeVisible();
  await page.goto("/app#/audit");
  await expect(page.getByText("No matching audit events")).toBeVisible();
});

test("corrupt demo progress recovers without retaining gateway payloads", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("actionproxy.agentDemoRuns.v1", "{not-json");
    window.localStorage.setItem(
      "actionproxy.agentDemoAutoContinue.v1",
      "corrupt",
    );
  });
  await page.goto("/app#/demo");
  const demo = page.locator(".agent-demo-panel");
  await expectStatus(
    demo.locator(".agent-step").filter({ hasText: "Search support policy" }),
    "Ready",
  );
  await demo.getByRole("button", { name: "Run next" }).click();
  await expectStatus(
    demo.locator(".agent-step").filter({ hasText: "Search support policy" }),
    "Complete",
  );

  const stored = await page.evaluate(() =>
    window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
  );
  expect(() => JSON.parse(stored ?? "")).not.toThrow();
  expect(stored).not.toContain("response");
  expect(stored).not.toContain("result");
  expect(stored).not.toContain("refund policy");
});

test("content-influence decisions are explained without rendering downstream hostile output", async ({
  page,
}) => {
  const toolCall = influencedToolCallFixture();
  await page.route(/\/v1\/tool-calls\?limit=100$/u, (route) =>
    route.fulfill({ json: { toolCalls: [toolCall] } }),
  );
  await page.route(`/v1/tool-calls/${toolCall.id}`, (route) =>
    route.fulfill({ json: toolCall }),
  );
  await page.goto(`/app#/tool-calls/${toolCall.id}`);

  const explanation = page.locator(".content-influence-panel");
  await expect(
    explanation.getByRole("heading", { name: "Content influence" }),
  ).toBeVisible();
  await expect(explanation).toContainText("allow");
  await expect(explanation).toContainText("require_approval");
  await expect(explanation).toContainText("public_untrusted");
  await expect(explanation).toContainText("Scope verified");
  await expect(
    page.getByText("HOSTILE_BROWSER_CANARY_DO_NOT_RENDER"),
  ).toHaveCount(0);
});

test("keyboard focus, reduced motion, Axe, and document width meet the Community baseline", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/app#/");

  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Refresh gateway data" }),
  ).toBeFocused();
  const focusStyle = await page.locator(":focus").evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
    };
  });
  expect(focusStyle.outlineStyle).not.toBe("none");
  expect(focusStyle.outlineWidth).toBeGreaterThanOrEqual(2);

  const demoLink = page
    .getByRole("navigation", { name: "Admin view" })
    .getByRole("link", { name: /^Demo lab/ });
  for (
    let index = 0;
    index < 8 &&
    !(await demoLink.evaluate((element) => element === document.activeElement));
    index += 1
  ) {
    await page.keyboard.press("Tab");
  }
  await expect(demoLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#\/demo$/u);

  const motion = await page
    .locator(".chatgpt-tunnel-panel")
    .evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        animationDuration: style.animationDuration,
        transitionDuration: style.transitionDuration,
      };
    });
  expect(durationMilliseconds(motion.animationDuration)).toBeLessThanOrEqual(
    0.01,
  );
  expect(durationMilliseconds(motion.transitionDuration)).toBeLessThanOrEqual(
    0.01,
  );

  for (const route of [
    "#/",
    "#/approvals",
    "#/authorized",
    "#/audit",
    "#/policy",
    "#/integrations",
    "#/demo",
    "#/missing",
  ]) {
    await page.goto(`/app${route}`);
    await expectNoDocumentOverflow(page);
    const results = await new AxeBuilder({ page }).analyze();
    const serious = results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    );
    expect(
      serious,
      `${route}: ${serious.map((violation) => violation.id).join(", ")}`,
    ).toEqual([]);
  }
});

async function expectCommunityRouteMissing(
  page: Page,
  route: string,
): Promise<void> {
  const response = await page.request.get(route);
  expect(response.status(), `${route} must not exist in Community`).toBe(404);
}

async function clearDemoState(page: Page): Promise<void> {
  // Playwright creates an isolated context for each test. Navigate once so the
  // origin exists, then clear this test's state directly; addInitScript would
  // run again on reload and erase the persistence behavior under test.
  await page.goto("/app#/");
  await page.evaluate(() => {
    window.localStorage.removeItem("actionproxy.agentDemoRuns.v1");
    window.localStorage.removeItem("actionproxy.agentDemoAutoContinue.v1");
  });
}

async function expectStatus(step: Locator, status: string): Promise<void> {
  await expect(
    step.locator(".agent-status").getByText(status, { exact: true }),
  ).toBeVisible();
}

async function fetchToolCalls(page: Page): Promise<ToolCallRecord[]> {
  const response = await page.request.get("/v1/tool-calls?limit=1000");
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { toolCalls: ToolCallRecord[] };
  return body.toolCalls;
}

async function fetchToolCall(
  page: Page,
  toolCallId: string,
): Promise<ToolCallRecord> {
  const response = await page.request.get(`/v1/tool-calls/${toolCallId}`);
  expect(response.ok()).toBeTruthy();
  return (await response.json()) as ToolCallRecord;
}

async function fetchExecutionAttempts(
  page: Page,
  toolCallId: string,
): Promise<ExecutionAttemptRecord[]> {
  const response = await page.request.get(
    `/v1/tool-calls/${encodeURIComponent(toolCallId)}/execution-attempts`,
  );
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as {
    attempts: ExecutionAttemptRecord[];
  };
  return body.attempts;
}

async function fetchAuditEvents(
  page: Page,
  toolCallId: string,
): Promise<AuditRecord[]> {
  const response = await page.request.get("/v1/audit?limit=1000");
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { events: AuditRecord[] };
  return body.events.filter((event) => event.toolCallId === toolCallId);
}

async function fetchPendingApprovals(page: Page): Promise<ApprovalRecord[]> {
  const response = await page.request.get("/v1/approvals/pending");
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { approvals: ApprovalRecord[] };
  return body.approvals;
}

async function waitForNewDemoEmailApproval(
  page: Page,
  existingToolCallIds: Set<string>,
): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const toolCall = (await fetchToolCalls(page)).find(
      (candidate) =>
        !existingToolCallIds.has(candidate.id) &&
        candidate.toolName === "gmail.send_email" &&
        candidate.metadata?.demo === "customer-support-agent" &&
        candidate.metadata?.visualStep === "send-email",
    );
    if (toolCall) {
      const approval = (await fetchPendingApprovals(page)).find(
        (candidate) => candidate.toolCallId === toolCall.id,
      );
      if (approval) return { approval, toolCall };
    }
    await page.waitForTimeout(250);
  }
  throw new Error("Timed out waiting for community demo email approval.");
}

async function waitForNewDemoToolCall(
  page: Page,
  existingToolCallIds: Set<string>,
  toolName: string,
  visualStep: string,
): Promise<ToolCallRecord> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const toolCall = (await fetchToolCalls(page)).find(
      (candidate) =>
        !existingToolCallIds.has(candidate.id) &&
        candidate.toolName === toolName &&
        candidate.metadata?.demo === "customer-support-agent" &&
        candidate.metadata?.visualStep === visualStep,
    );
    if (toolCall) return toolCall;
    await page.waitForTimeout(250);
  }
  throw new Error(
    `Timed out waiting for community demo tool call ${toolName}.`,
  );
}

async function expandAuditGroup(group: Locator): Promise<void> {
  await expect(group).toBeVisible();
  const toggle = group.getByRole("button", { name: /Show \d+ events?/ });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.click();
  await expect(
    group.getByRole("button", { name: "Hide events" }),
  ).toHaveAttribute("aria-expanded", "true");
}

async function expectNoDocumentOverflow(page: Page): Promise<void> {
  const geometry = await page.evaluate(() => ({
    bodyWidth: document.body.scrollWidth,
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
  }));
  expect(geometry.documentWidth, JSON.stringify(geometry)).toBeLessThanOrEqual(
    geometry.viewportWidth + 1,
  );
  expect(geometry.bodyWidth, JSON.stringify(geometry)).toBeLessThanOrEqual(
    geometry.viewportWidth + 1,
  );
}

function durationMilliseconds(value: string): number {
  const first = value.split(",")[0]?.trim() ?? "0s";
  const numeric = Number.parseFloat(first);
  if (!Number.isFinite(numeric)) return Number.POSITIVE_INFINITY;
  return first.endsWith("ms") ? numeric : numeric * 1_000;
}

function influencedToolCallFixture() {
  return {
    agentId: "community-browser-test-agent",
    contentInfluence: {
      baseDecision: "allow",
      bindingHash: "sha256:browser-binding",
      effectiveDecision: "require_approval",
      evaluatedAt: "2026-07-19T10:00:00.000Z",
      exposureRevision: 3,
      exposureSnapshotHash: "sha256:browser-exposure",
      influenceScope: { id: "scope_browser_test", verified: true },
      observedSources: ["public_untrusted"],
      policy: {
        versionHash: "sha256:browser-policy",
        versionId: "policy-browser-test",
      },
      selectedRule: {
        allowFrom: ["none", "organization_managed"],
        otherwise: "required",
      },
      sourceCount: 1,
      sourceCountIsLowerBound: false,
      sourceReferences: [
        {
          integrity: "public_untrusted",
          sourceId: "hostile-browser-source",
          sourceToolCallId: "toolcall_hostile_source",
        },
      ],
      version: "actionproxy.content-influence.v1",
    },
    createdAt: "2026-07-19T10:00:00.000Z",
    decision: "require_approval",
    id: "toolcall_influence_browser",
    input: { noteId: "note_browser_test" },
    metadata: {},
    reason: "Browser-test influence explanation",
    requestedBy: "browser-test@example.com",
    result: { text: "HOSTILE_BROWSER_CANARY_DO_NOT_RENDER" },
    status: "pending_approval",
    toolName: "research.notes.append",
    updatedAt: "2026-07-19T10:00:00.000Z",
  };
}
