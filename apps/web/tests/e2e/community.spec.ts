import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";

interface ToolCallRecord {
  agentId?: string;
  createdAt?: string;
  decision?: string;
  id: string;
  input?: Record<string, unknown>;
  metadata: Record<string, unknown>;
  reason?: string;
  requestedBy?: string;
  status: string;
  toolName: string;
  updatedAt?: string;
}

interface ApprovalRecord {
  createdAt?: string;
  id: string;
  originalInput?: Record<string, unknown>;
  requestedBy?: string;
  status?: string;
  toolCallId: string;
  updatedAt?: string;
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
  await expect(nav.getByRole("link", { name: /^Quickstart/ })).toBeVisible();
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
  await expect(
    page.getByRole("heading", {
      name: "See ActionProxy control a tool call",
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Local lifecycle proof" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Connect ChatGPT" }),
  ).toHaveCount(0);

  await page.getByRole("link", { name: /Connect ChatGPT/ }).click();
  await expect(page).toHaveURL(/#\/demo\?journey=chatgpt$/u);
  const tunnelPanel = page.locator(".chatgpt-tunnel-panel");
  await expect(
    tunnelPanel.getByRole("heading", { name: "Connect ChatGPT" }),
  ).toBeVisible();
  await expect(
    tunnelPanel.locator(".status-badge", { hasText: "Setup not checked" }),
  ).toBeVisible();
  const tunnelDetails = tunnelPanel.locator(".chatgpt-tunnel-details");
  await expect(tunnelDetails).not.toHaveAttribute("open", "");
  await tunnelDetails.locator("summary").click();
  await expect(
    tunnelPanel.getByRole("heading", { name: "Confirm access first" }),
  ).toBeVisible();
  await expect(tunnelPanel).toContainText(
    "ChatGPT workspace access and OpenAI Platform tunnel permissions are separate",
  );
  await expect(tunnelPanel).toContainText("target ChatGPT workspace");
  await expect(
    tunnelPanel.getByRole("heading", { name: "Exactly three mock tools" }),
  ).toBeVisible();
  const fixtureTools = tunnelPanel.locator(".chatgpt-tunnel-tools li code");
  await expect(fixtureTools).toHaveText([
    "docs.search",
    "gmail.send_email",
    "dangerous.delete_customer",
  ]);
  await expect(
    tunnelPanel.getByRole("link", { name: /ChatGPT app settings/ }),
  ).toHaveAttribute("href", "https://chatgpt.com/plugins");
  await expect(tunnelPanel).toContainText(
    "External setup links reviewed 2026-08-03.",
  );
  const manualSetup = tunnelPanel.locator(".chatgpt-manual-setup");
  await expect(manualSetup).not.toHaveAttribute("open", "");
  await manualSetup.locator("summary").click();
  await expect(tunnelPanel.getByLabel("OpenAI tunnel ID")).toBeVisible();
  await expect(tunnelPanel.getByLabel(/runtime key/i)).toHaveCount(0);
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
  await expect(
    page.getByRole("heading", { name: "Local lifecycle proof" }),
  ).toHaveCount(0);

  const tunnelId = "tunnel_0123456789abcdef0123456789abcdef";
  await tunnelPanel.getByLabel("OpenAI tunnel ID").fill(tunnelId);
  const manualCommand = manualSetup.locator(".chatgpt-tunnel-command");
  await expect(manualCommand).toContainText(tunnelId);
  await expect(manualCommand).not.toContainText(/runtime[-_ ]key/i);
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
  await agentDemo.getByRole("button", { name: "Run guided proof" }).click();
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
  await expect(page).toHaveTitle("Approval waiting · ActionProxy");
  await expect(
    page
      .locator(".quickstart-pending-banner")
      .getByText(/Action paused. Nothing has executed./i),
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
  ).toHaveAttribute(
    "href",
    `#/approvals/${created.approval.id}?returnTo=%23%2Fdemo%3Fjourney%3Dlocal%26guided%3D1`,
  );
  const storedProgress = await page.evaluate(() =>
    window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
  );
  expect(storedProgress).not.toContain("response");
  expect(storedProgress).not.toContain("result");
  expect(storedProgress).not.toContain("customer@example.com");
  const storedRunIds = JSON.parse(storedProgress ?? "{}") as Record<
    string,
    Record<string, unknown>
  >;
  for (const storedRun of Object.values(storedRunIds)) {
    expect(
      Object.keys(storedRun).every((key) =>
        ["approvalId", "toolCallId"].includes(key),
      ),
    ).toBe(true);
  }
  expect(
    await page.evaluate(() =>
      window.localStorage.getItem("actionproxy.agentDemoAutoContinue.v1"),
    ),
  ).toBeNull();

  expect(await fetchExecutionAttempts(page, created.toolCall.id)).toEqual([]);
  const preApprovalEventTypes = (
    await fetchAuditEvents(page, created.toolCall.id)
  ).map((event) => event.type);
  expect(preApprovalEventTypes).not.toContain("execution.attempt_dispatched");
  expect(preApprovalEventTypes).not.toContain("execution.attempt_completed");
  expect(preApprovalEventTypes).not.toContain("receipt.created");
  expect(preApprovalEventTypes).not.toContain("tool_call.executed");

  await agentDemo.getByRole("link", { name: "Review this approval" }).click();
  await expect(page).toHaveURL(
    new RegExp(
      `#\\/approvals\\/${created.approval.id}\\?returnTo=%23%2Fdemo%3Fjourney%3Dlocal%26guided%3D1$`,
      "u",
    ),
  );
  await expect(
    page.getByRole("heading", { name: "Review the proposed email" }),
  ).toBeVisible();
  await expect(page.locator(".approval-detail .status-badge")).toHaveText(
    "Waiting for your decision",
  );
  await expect(
    page.getByRole("heading", { name: "Email waiting for review" }),
  ).toBeVisible();
  await expect(
    page.getByText("customer@example.com", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Approve exact proposal" }).click();
  await expect(
    page.getByText("Executed successfully exactly once."),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Return now" })).toHaveAttribute(
    "href",
    "#/demo?journey=local&guided=1",
  );
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

  await page.getByRole("link", { name: "Return now" }).click();
  await expect(page).toHaveURL(/#\/demo\?journey=local&guided=1$/u);
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
  await expect(
    page.getByRole("heading", {
      name: "Quickstart complete: audit chain verified",
    }),
  ).toBeVisible();

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

test("deep-linked ChatGPT quickstart scopes progress to its live companion session", async ({
  page,
}) => {
  const sessionId = "123e4567-e89b-42d3-a456-426614174000";
  await page.route(`/v1/demo/quickstart/status/${sessionId}`, (route) =>
    route.fulfill({
      json: {
        approvalTimeoutMs: 300_000,
        checks: [
          { id: "gateway", state: "pass" },
          { id: "tool_discovery", state: "pass" },
          { id: "tunnel_readiness", state: "pass" },
        ],
        journey: "chatgpt",
        schemaVersion: "actionproxy.quickstart.v1",
        sessionId,
        setupDetails: {
          composeVersion: "2.35.1",
          dockerVersion: "28.1.1",
          nodeVersion: "24.11.0",
          port: 18787,
          projectName: "actionproxy-first-run-0123456789",
          runtimeKeyExcludedFromDocker: true,
        },
        setupStage: "tunnel_ready",
        startedAt: "2999-08-02T08:00:00.000Z",
        tunnelUiUrl: "http://127.0.0.1:4040",
        updatedAt: "2999-08-02T08:00:01.000Z",
      },
    }),
  );

  await page.goto(
    `/app#/demo?journey=chatgpt&session=${encodeURIComponent(sessionId)}`,
  );

  await expect(
    page.getByRole("heading", { name: "Secure tunnel ready" }),
  ).toBeVisible();
  await expect(page.getByText("0/3 complete")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Copy allowed search prompt" }),
  ).toBeEnabled();
  await expect(
    page.getByRole("button", {
      name: "Copy approval-required email prompt",
    }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Copy denied deletion prompt" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("link", { name: /Open tunnel health UI/ }),
  ).toHaveAttribute("href", "http://127.0.0.1:4040");
});

test("pending approval survives reload and can be rejected without an email effect", async ({
  page,
}) => {
  const existingToolCallIds = new Set(
    (await fetchToolCalls(page)).map((toolCall) => toolCall.id),
  );
  await page.goto("/app#/demo");
  const agentDemo = page.locator(".agent-demo-panel");
  await agentDemo.getByRole("button", { name: "Run guided proof" }).click();
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

  await agentDemo.getByRole("link", { name: "Review this approval" }).click();
  await page.getByRole("button", { name: "Reject" }).click();
  await page
    .getByLabel("Rejection reason")
    .fill("Intentional Community rejection-path test.");
  await page.getByRole("button", { name: "Confirm rejection" }).click();
  await expect(page.getByText("Rejected. Nothing was sent.")).toBeVisible();
  await expect
    .poll(async () => (await fetchToolCall(page, created.toolCall.id)).status)
    .toBe("rejected");

  await page.getByRole("link", { name: "Return now" }).click();
  await expect(page).toHaveURL(/#\/demo\?journey=local&guided=1$/u);
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
  await demo.getByText("Run step by step").click();
  await demo.getByRole("button", { name: "Run next step" }).click();
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
  expect(
    await page.evaluate(() =>
      window.localStorage.getItem("actionproxy.agentDemoAutoContinue.v1"),
    ),
  ).toBeNull();
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
    .getByRole("link", { name: /^Quickstart/ });
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

  await page.getByRole("link", { name: /Connect ChatGPT/ }).click();

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
    "#/demo?journey=chatgpt",
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

test("first-run visual states remain reviewable", async ({
  page,
}, testInfo) => {
  test.skip(
    testInfo.project.name !== "desktop" || process.platform !== "darwin",
    "The four-project matrix checks responsive behavior; canonical release-quality visual baselines use desktop macOS.",
  );

  const sessionId = "123e4567-e89b-42d3-a456-426614174000";
  let setupStage: "failed" | "tunnel_ready" = "failed";
  let toolCalls: ToolCallRecord[] = [];
  let approvals: ApprovalRecord[] = [];
  let auditEvents: AuditRecord[] = [];
  await page.route(`/v1/demo/quickstart/status/${sessionId}`, (route) =>
    route.fulfill({
      json: visualQuickstartStatus(sessionId, setupStage),
    }),
  );
  await page.route(/\/v1\/tool-calls\?limit=100$/u, (route) =>
    route.fulfill({ json: { toolCalls } }),
  );
  await page.route(/\/v1\/approvals\/pending$/u, (route) =>
    route.fulfill({ json: { approvals } }),
  );
  await page.route(/\/v1\/audit\?limit=500$/u, (route) =>
    route.fulfill({ json: { events: auditEvents } }),
  );
  await page.route("/v1/audit/verify", (route) =>
    route.fulfill({
      json: { checked: auditEvents.length, errors: [], valid: true },
    }),
  );

  await page.goto("/app#/demo");
  await expect(page.locator(".quickstart-chooser")).toHaveScreenshot(
    "first-run-chooser.png",
    visualSnapshotOptions,
  );

  await page.goto(
    `/app#/demo?journey=chatgpt&session=${encodeURIComponent(sessionId)}`,
  );
  await expect(
    page.getByRole("heading", { name: "Setup needs attention" }),
  ).toBeVisible();
  await expect(page.locator(".chatgpt-tunnel-panel")).toHaveScreenshot(
    "first-run-remediation.png",
    visualSnapshotOptions,
  );

  setupStage = "tunnel_ready";
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Secure tunnel ready" }),
  ).toBeVisible();
  await expect(page.locator(".chatgpt-tunnel-panel")).toHaveScreenshot(
    "first-run-tunnel-ready.png",
    visualSnapshotOptions,
  );

  const createdAt = new Date().toISOString();
  const email = visualTunnelCall({
    createdAt,
    decision: "require_approval",
    id: "visual_email_call",
    sessionId,
    status: "pending_approval",
    toolName: "gmail.send_email",
  });
  toolCalls = [email];
  approvals = [
    {
      createdAt,
      id: "visual_email_approval",
      originalInput: email.input ?? {},
      requestedBy: email.requestedBy ?? "chatgpt-tunnel-demo@example.local",
      status: "pending",
      toolCallId: email.id,
      updatedAt: createdAt,
    },
  ];
  await page.reload();
  await expect(page.locator(".quickstart-pending-banner")).toBeVisible();
  await expect(page.locator(".quickstart-pending-banner")).toHaveScreenshot(
    "first-run-approval-waiting.png",
    visualSnapshotOptions,
  );

  const search = visualTunnelCall({
    createdAt,
    decision: "allow",
    id: "visual_search_call",
    sessionId,
    status: "executed",
    toolName: "docs.search",
  });
  const completedEmail = { ...email, status: "executed" as const };
  const deletion = visualTunnelCall({
    createdAt,
    decision: "deny",
    id: "visual_delete_call",
    sessionId,
    status: "blocked",
    toolName: "dangerous.delete_customer",
  });
  toolCalls = [search, completedEmail, deletion];
  approvals = [];
  auditEvents = [
    visualAuditEvent("search-allowed", "policy.allow", search.id),
    visualAuditEvent("search-executed", "tool_call.executed", search.id),
    visualAuditEvent("email-held", "policy.require_approval", email.id),
    visualAuditEvent("email-created", "approval.created", email.id),
    {
      ...visualAuditEvent("email-approved", "approval.approved", email.id),
      data: { inputDecision: "original" },
    },
    visualAuditEvent(
      "email-dispatched",
      "execution.attempt_dispatched",
      email.id,
    ),
    visualAuditEvent("email-executed", "tool_call.executed", email.id),
    visualAuditEvent("delete-denied", "policy.deny", deletion.id),
  ];
  await page.reload();
  await expect(
    page.getByRole("heading", {
      name: "You governed three Quickstart MCP tool calls from your Mac",
    }),
  ).toBeVisible();
  await expect(page.locator(".chatgpt-verified-proof")).toHaveScreenshot(
    "first-run-completion.png",
    visualSnapshotOptions,
  );
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

const visualSnapshotOptions = {
  animations: "disabled" as const,
  caret: "hide" as const,
  maxDiffPixelRatio: 0.01,
  threshold: 0.2,
};

function visualQuickstartStatus(
  sessionId: string,
  setupStage: "failed" | "tunnel_ready",
) {
  const tunnelReady = setupStage === "tunnel_ready";
  return {
    approvalTimeoutMs: 300_000,
    checks: [
      { id: "node", state: "pass" },
      { id: "docker_cli", state: "pass" },
      tunnelReady
        ? { id: "docker_daemon", state: "pass" }
        : {
            id: "docker_daemon",
            remediationCode: "docker_not_running",
            state: "action_required",
          },
      { id: "compose", state: tunnelReady ? "pass" : "pending" },
      { id: "gateway", state: tunnelReady ? "pass" : "pending" },
      { id: "storage", state: tunnelReady ? "pass" : "pending" },
      { id: "loopback", state: tunnelReady ? "pass" : "pending" },
      { id: "tool_discovery", state: tunnelReady ? "pass" : "pending" },
      { id: "tunnel_client", state: tunnelReady ? "pass" : "pending" },
      { id: "tunnel_doctor", state: tunnelReady ? "pass" : "pending" },
      { id: "tunnel_readiness", state: tunnelReady ? "pass" : "pending" },
    ],
    journey: "chatgpt",
    schemaVersion: "actionproxy.quickstart.v1",
    sessionId,
    setupDetails: tunnelReady
      ? {
          composeVersion: "2.35.1",
          dockerVersion: "28.1.1",
          nodeVersion: "24.11.0",
          port: 18787,
          projectName: "actionproxy-first-run-0123456789",
          runtimeKeyExcludedFromDocker: true,
        }
      : undefined,
    setupStage,
    startedAt: "2026-08-02T08:00:00.000Z",
    tunnelUiUrl: tunnelReady ? "http://127.0.0.1:4040/ui" : undefined,
    updatedAt: "2026-08-02T08:00:01.000Z",
  };
}

function visualTunnelCall({
  createdAt,
  decision,
  id,
  sessionId,
  status,
  toolName,
}: {
  createdAt: string;
  decision: "allow" | "deny" | "require_approval";
  id: string;
  sessionId: string;
  status: ToolCallRecord["status"];
  toolName: string;
}): ToolCallRecord {
  const input =
    toolName === "gmail.send_email"
      ? {
          body: "Your request is ready.",
          subject: "Refund update",
          to: "customer@example.com",
        }
      : {};
  return {
    agentId: "actionproxy-chatgpt-tunnel-demo",
    createdAt,
    decision,
    id,
    input,
    metadata: {
      actionproxyQuickstartOrigin: "secure_mcp_tunnel",
      actionproxyQuickstartSessionId: sessionId,
      mcpServer: "chatgpt-tunnel-demo",
    },
    reason: "Deterministic visual acceptance fixture",
    requestedBy: "chatgpt-tunnel-demo@example.local",
    status,
    toolName,
    updatedAt: createdAt,
  };
}

function visualAuditEvent(
  id: string,
  type: string,
  toolCallId: string,
): AuditRecord & {
  data: Record<string, unknown>;
  id: string;
  timestamp: string;
} {
  return {
    data: {},
    id: `visual-${id}`,
    timestamp: "2026-08-02T08:00:02.000Z",
    toolCallId,
    type,
  };
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
