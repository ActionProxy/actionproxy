# Policy spec

ActionProxy policy is deterministic YAML. The loaded file is the enforcement
source of truth for every proposed tool call.

The versioned machine-readable data model is
[`schemas/actionproxy.policy.v1.schema.json`](../schemas/actionproxy.policy.v1.schema.json).
It uses JSON Schema draft 2020-12 and validates the JSON data model represented
by YAML. Conventional editor associations for `actionproxy.policy.yaml`,
`actionproxy.policy.yml`, `*.policy.yaml`, and `*.policy.yml` are in
[`schemas/editor-associations.json`](../schemas/editor-associations.json).

The schema is deterministic generated output. Change the runtime parser and
generator together, then run:

```bash
node scripts/generate-config-schemas.mjs
node scripts/generate-config-schemas.mjs --check
node --test scripts/generate-config-schemas.test.mjs
```

The v1 parser retains compatibility for some unknown legacy fields, and JSON
Schema cannot express every trusted-context or cross-field enforcement rule.
Passing editor validation is useful authoring feedback; it is not a substitute
for loading the policy through ActionProxy and proving the lifecycle.

## Minimal policy

```yaml
version: 1

default:
  approval: required
  risk: unknown
  reason: "Unknown tools require approval by default."

tools:
  docs.search:
    approval: never
    risk: read_only
    reason: "Search is read-only."

  gmail.send_email:
    approval: required
    risk: external_communication
    reason: "External email requires approval."
    notify:
      channels:
        - slack.default
        - telegram.default
        - email.default

  dangerous.delete_customer:
    approval: deny
    risk: destructive
    reason: "Customer deletion is blocked."
```

`default` is mandatory. A rule must contain `approval`; every other field is
optional. Unknown top-level, rule, and legacy extension fields are ignored in
v1 for compatibility; `resultSource` and `influence` reject unknown fields.

## Decisions

| YAML value | Effective decision | Meaning                                         |
| ---------- | ------------------ | ----------------------------------------------- |
| `never`    | `allow`            | The call may continue without a human decision. |
| `required` | `require_approval` | Create a pending approval.                      |
| `deny`     | `deny`             | Block before authorization or dispatch.         |

The bundled policy deliberately requires approval for unknown tools and denies
`dangerous.delete_customer`.

## Matching

Rules match an exact tool name first, then a terminal wildcard such as
`salesforce.*`, then `default`. The selected source appears in the decision
trace. A wildcard is a simple namespace prefix, not a regular expression.

A rule may add typed `conditions`. All conditions on the selected rule must
match or evaluation falls through to the wildcard/default path. Community
request adapters derive trusted condition context from the canonical action
request; ordinary metadata cannot make a value authoritative.

Useful Community condition keys are:

- `actionId`: exact tool name;
- `operationKind`: `read`, `write`, `external_send`, `financial`, or `delete`;
- `customerVisible`: boolean when an adapter has a trusted mapping;
- `recipientDomain`: `internal` or `external`;
- `amount`: a number or `{ gt, gte, lt, lte, eq }` threshold;
- `currency`: exact currency string;
- `risk`: server-derived risk context when available.

If an adapter cannot derive a trusted value, the value is absent and that
conditional rule does not match. See `canonical-action-request-v1.md`.

## Approval routing

```yaml
tools:
  payroll.update:
    approval: required
    risk: sensitive_write
    approvers:
      groups: [payroll-admins]
      users: [u_alice]
      requiredApprovals: 2
      separationOfDuties: true
```

`approvers.users` and `approvers.groups` resolve against the workspace approver
directory. If neither is supplied, enabled users marked `defaultApprover` are
eligible.

`requiredApprovals` defaults to `1` and is limited to `10` by the policy parser.
Intermediate decisions remain pending. With more than one required approval,
edited input is rejected because edited-payload consensus is not implemented.

`separationOfDuties: true` prevents the authenticated submitter from approving
or rejecting their own request.

## Notification routing

```yaml
notify:
  channels:
    - slack.default
    - telegram.default
    - email.default
```

Notification channels choose delivery destinations, not approval authority. If
the list is omitted, enabled default channels are used. A missing, disabled, or
failing channel records delivery failure and does not approve, reject, block,
or execute the call. Allow and deny rules do not send approval notifications.

The browser console remains an approval surface even when no external channel
is configured.

## External execution

```yaml
tools:
  crm.update_record:
    approval: required
    externalExecution:
      grantTtlSeconds: 300
      requireGrantConsumption: true
```

`grantTtlSeconds` is between `1` and `86400`. An authorized external action
returns a signed receipt and one-time execution grant. The runner consumes the
grant before dispatch and reports an immutable outcome afterward. The grant is
bound to the exact action, approved input, receipt, policy, expiry, and nonce.

An external rule does not make ActionProxy a downstream connector or transfer
credential custody to it.

## Redaction

```yaml
redaction:
  fields:
    - input.body
    - originalInput.body
  replacement: "[redacted]"
```

API and UI reads always mask common secret-shaped keys and may additionally
mask configured field paths. Redaction is a presentation control. Original
inputs, edited inputs, results, and audit payloads remain in storage and must be
protected as sensitive data.

## Result sources

`resultSource` classifies model-visible output from an administrator-reviewed
tool or adapter.

```yaml
tools:
  company.docs.search:
    approval: never
    risk: closed_world_read
    resultSource:
      integrity: organization_managed
      sourceId: company-docs

  web.fetch:
    approval: required
    risk: open_world_read
    resultSource:
      integrity: public_untrusted
      sourceId: public-web

  local.counter:
    approval: never
    resultSource: none
```

Allowed integrity values are:

- `organization_managed`;
- `verified_publisher`;
- `authenticated_external`;
- `public_untrusted`;
- `unknown`.

`none` is not an integrity class. It means a reviewed tool does not release
external content to the model. A rule with `risk: open_world_read` must use
`public_untrusted`; any other value fails policy parsing.

Integrity records reviewed origin. It does not grant instruction authority,
declare content safe, rewrite an MCP result, or trust a hostname/provider name.
Tool descriptions, caller metadata, annotations, result `_meta`, and child
assertions cannot assign or clear integrity.

## Content-influence guard

An `influence` guard narrows a later action according to all source classes
already released in its verified MCP influence scope.

```yaml
tools:
  memory.write:
    approval: required
    risk: persistent_memory
    resultSource: none
    influence:
      allowFrom:
        - none
        - organization_managed
      otherwise: deny
```

`allowFrom` is a non-empty set drawn from the five integrity classes plus
`none`. The values are not ordered scores. `otherwise` is only `required` or
`deny`.

The guard intersects with ordinary policy:

- a base denial remains denial;
- a base approval can never become automatic execution;
- a missing or unverified scope becomes `unknown`, not `none`;
- missing/overflowed evidence or unavailable storage becomes `unknown`;
- output from an unclassified tool becomes `unknown` while protection is
  active.

ActionProxy stores the opaque scope, bounded exposure snapshot, observed
classes, source call references, base/effective decisions, policy identity, and
monotonic exposure revision. It revalidates these bindings before approval
finalization and immediately before execution. A stale binding fails before the
executor is called.

Enabling the guard is a security-boundary transition. Start a fresh MCP wrapper
process or signed session and clear earlier agent context where possible. A new
scope isolates future ActionProxy evidence; it does not prove the model forgot
previous content.

## Remediation

A successful outcome may describe a remediation action. Submitting it creates a
new linked tool call that passes through normal policy, approval, receipt,
grant, execution, and audit handling. It never mutates the original execution
record or claims universal rollback.

Policy should explicitly cover remediation tools that can overwrite business
state. Irreversible actions should expose no remediation or an honest
compensating action supplied by the downstream system.

## Policy editor and detector

The local console starts in read-only policy mode. Saving replaces the local
YAML file and updates policy for new submissions; existing records are not
rewritten.

The detector stores observed tool names, source metadata, schema hashes,
coverage, and deterministic suggestions—not raw inputs. Default-only matches
remain safe but are surfaced for review. Applying a suggestion creates a normal
YAML rule. Suggestions are advisory and cannot bypass policy validation.

## Versioning and changes

The policy `version` participates in decision evidence and authorization
revalidation. Operators should review and commit policy changes like code. A
change can invalidate a pending approval or grant; ActionProxy fails closed
rather than executing with stale authority.
