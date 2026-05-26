# Argus — Project Story

## Inspiration

My background is in network engineering. I spend a lot of time
thinking like an attacker (I've never attacked before) — mapping networks and finding weak points. That perspective changes how you see incident
response.

When you do enough pentests, you stop asking "can this system be breached?" and start
asking "how long would it take anyone to *notice*?" The honest answer, more often than
not, is: too long.

A successful breach rarely announces itself. It starts quietly — a brute force attempt
that blends into the noise, a login that looks almost legitimate, a lateral move disguised
as normal traffic. By the time a SOC analyst has manually correlated enough log lines to
reconstruct what happened, the attacker has had hours, sometimes days, of uncontested
access. Data has moved. Credentials have been harvested. Persistence has been
established. The window that matters — the gap between initial compromise and
containment — closes slowly when humans have to do the work alone.

That is the problem Argus is built to solve. Not to replace the analyst, but to collapse
that window. To take the investigation work that used to take hours and compress it into
seconds, so the analyst can spend their time on decisions, not on digging.

---

## What It Does

Argus is an agentic incident responder built on Splunk. When Splunk fires a security
alert, Argus autonomously investigates it using an LLM-driven reasoning loop — querying
Splunk for evidence, correlating events across log sources, and building a complete
picture of what happened. The output is a structured incident report containing a full
attack chain timeline, MITRE ATT\&CK mapping, severity classification, affected systems,
and specific remediation steps.

The core is a planner loop. At each iteration, the LLM receives the current investigation
state — what has been found so far, what actions have already been taken — and chooses
what to investigate next from a set of available tools. A brute force alert that reveals
a successful login triggers a different investigation path than one that doesn't. The
reasoning is visible in real time through the agent log in the UI, showing every decision
and the evidence that drove it.

The system is built on:

- **Splunk Enterprise** for data ingestion, search, and alerting
- **Python + FastAPI** for the backend agent orchestration
- **Google Gemini** as the primary LLM, with OpenAI and Splunk's hosted model as alternatives
- **WebSockets** to stream agent reasoning steps to the frontend in real time
- **React + Tailwind CSS** for the SOC dashboard UI
- **BOTS v3 (Boss of the SOC)** as the demo dataset
- A static MITRE ATT\&CK keyword map and a bundled IOC dataset for reliable,
  latency-free threat correlation

---

## How I Built It

The build followed four phases across the hackathon window.

**Phase 1** was Splunk — getting BOTS v3 indexed correctly, writing the SPL saved
searches that detect attack patterns, and configuring Splunk's alert engine to POST a
webhook to the FastAPI backend when a condition fires. This sounds straightforward. It
wasn't. The BOTS dataset has dozens of sourcetypes with inconsistent field naming, and
getting the right data into the right queries required a lot of time in the Search &
Reporting interface before a single line of Python was written.

**Phase 2** was the agent. The LLM provider was abstracted from day one — a base class
with three implementations (Gemini, OpenAI, Splunk), switchable via a single environment
variable. This turned out to be one of the most important decisions in the project, because
Splunk's hosted model behaves differently from what development with Gemini had established.
Having a clean fallback meant that model instability never blocked progress.

The planner loop itself — the mechanism by which the LLM chooses its next action based on
accumulated findings — required careful prompt engineering. The LLM needs to understand not
just what actions are available, but which ones are still available (actions already taken
are excluded from the next prompt), and it needs to choose based on evidence rather than
habit. Getting consistent, well-reasoned JSON output from the planner prompt across
different input states took significant iteration.

**Phase 3** was the frontend and full integration. The UI was built in component priority
order: the agent reasoning log first, then the
attack timeline, then the alert feed, then the recommendations panel. WebSocket
integration for real-time agent step streaming came after the agent itself was stable —
wiring an unstable backend to a live UI would have made debugging much harder.

**Phase 4** was hardening. The demo scenario was run repeatedly until the full
investigation — from alert firing to complete incident report — completed consistently
in under 20 seconds. The BOTS C2 IP addresses were extracted and added to the bundled
IOC dataset so threat correlation fires reliably during the demo without any external
API dependency.

---

## Challenges

**The backend agent was the hardest part to get right.** Building a system where an LLM
drives its own investigation — choosing tools, reasoning over results, deciding when it
has enough information — is straightforward in theory and genuinely difficult in practice.
The planner prompt has to be precise enough to produce valid JSON consistently while
flexible enough to handle wildly different input states. Early versions of the loop would
choose the same action twice, or pick `generate_report` after a single finding, or produce
planner output that wasn't parseable JSON. Each of these failure modes required a different
fix — action history tracking in the state, explicit rules in the prompt, structured output
enforcement, retry logic with error context fed back into the next call.

**BOTS v3 on Splunk was its own challenge.** The dataset is rich, but loading it correctly,
understanding which sourcetypes contain which fields, and writing SPL that returns reliable
results across the dataset's quirks took longer than expected. Several early SPL queries
produced empty results not because the data wasn't there but because the field names
differed by sourcetype. The lesson: understand the data before building the queries that
depend on it.

**Getting Splunk to reliably send webhooks to Argus** required understanding Splunk's
alert action system in more depth than the documentation initially suggested. Timing,
payload structure, and the exact configuration of the saved search conditions all
affect whether the webhook fires, when it fires, and what it contains. This was debugged
through a combination of Splunk's internal logs and a simple logging endpoint in FastAPI
that printed every incoming payload.

**The security review after the initial build revealed real problems.** The first version
of the project used full JWT authentication with httpOnly cookies, live external threat
intelligence feeds, and an LLM-driven MITRE classification system. Each of these
introduced complexity and failure modes that would have been difficult to manage within
the hackathon timeline, and two of them introduced genuine reliability risks for the demo.
After reviewing the project critically:

- JWT was replaced with a simplified session token. The auth logic works correctly, adds
  no fragility, and the production design (JWT with refresh tokens and RBAC) is described
  in the write-up.
- External threat intel feeds were replaced with a bundled static IOC dataset. No rate
  limits, no latency, no external dependency. The correlation fires instantly and reliably
  every time.
- MITRE mapping was replaced with a deterministic keyword-to-technique dictionary.
  Thirty minutes to implement, perfectly adequate for the use case, and completely
  predictable in behavior.
- LLM provider coupling was broken by abstracting the provider behind an interface with
  three implementations. If Splunk's hosted model is unavailable or produces malformed
  output, one environment variable switches the entire system to a working alternative.

The willingness to make these cuts — to trade sophistication for correctness and
reliability — was arguably the most important engineering decision in the project.
A demo that works perfectly is worth more than a sophisticated system that occasionally
doesn't.

---

## What I Learned

**Agentic systems fail in specific, predictable ways** if you don't design against them
from the start. Action deduplication, state management, structured output enforcement,
and fallback logic are not optional polish — they are the difference between a reasoning
loop and a loop that occasionally reasons.

**The LLM abstraction layer was worth every minute it took to build.** It turned a
potential single point of failure into a configuration switch. In a real production system,
this pattern — provider-agnostic LLM interface with environment-driven selection — would
be essential. In a hackathon, it was the difference between a stable demo and a broken one.

**Splunk is a serious platform that rewards serious investment.** SPL is expressive and
powerful, the alert engine is flexible, and the data pipeline is reliable. But it assumes
you understand the data you're working with. Time spent understanding BOTS before writing
queries was time saved debugging later.

**Security review should happen before, not after, the build.** The vulnerabilities and
design problems found during the post-build review were all things that could have been
caught earlier with a more critical eye at the design stage. They were caught in time,
which is what matters — but finding them earlier would have saved rebuild time.

**Simplicity is a security property.** Every external dependency, every complex auth
flow, every LLM-driven classification that could have been a keyword lookup — these are
all surfaces where things can go wrong. In a system designed to help analysts respond
to incidents, reliability is not a nice-to-have. Argus is built to be simple where
simplicity is correct, and complex only where complexity is necessary.

---

## What's Next for Argus

The hackathon build is a working proof of concept for a genuinely useful class of tool.
Several directions are worth exploring:

- **Multi-alert correlation** — Argus currently investigates one alert at a time.
  Correlating patterns across multiple simultaneous alerts would allow it to detect
  coordinated attacks and campaign-level activity.
- **Feedback loop** — Allowing analysts to mark investigation paths as correct or
  incorrect would let the planner prompts improve over time based on real-world outcomes.
- **Write-capable tools** — Under appropriate authorization controls, Argus could take
  containment actions directly: isolating a host, blocking an IP, disabling an account.
  The read-only constraint is correct for a first build; it's a deliberate choice to
  revisit with proper guardrails.
- **Broader log source support** — The current tool implementations are tuned for the
  BOTS v3 dataset. Extending them to handle cloud provider logs, EDR telemetry, and
  container environments would make Argus useful across a wider range of real-world
  deployments.
- **Persistence** — Incidents and reports currently live in memory and are lost on restart.
  A database backend would make the full investigation history durable and queryable.
- **Notifications** — Analysts away from the dashboard should receive an alert when
  Argus classifies an incident as HIGH or CRITICAL.
- **Multi-user support** — Role-based access control and an audit log so multiple analysts
  can share a deployment without stepping on each other.
- **Alert queue management** — Under sustained alert load, investigations currently run
  concurrently without priority ordering. A proper queue with severity-based scheduling
  would ensure critical alerts are never delayed by lower-priority work.
- **Dynamic SPL generation for real-world deployments** — The current tool implementations
  contain hardcoded SPL queries written specifically for the BOTS v3 dataset: fixed
  sourcetypes, known field names, and pre-selected indicators. In a live Splunk deployment,
  every environment is different — sourcetypes, index names, CIM compliance, and field
  naming conventions all vary by organisation. The path to making Argus environment-agnostic
  is to replace the static query library with LLM-generated SPL. When an alert arrives, the
  planner would first run a schema-discovery phase — querying `| metadata type=sourcetypes`
  and `| fieldsummary` against the relevant index — then construct queries tailored to what
  actually exists in that environment. Combined with a per-deployment tool-configuration
  file that maps common alert types to candidate sourcetypes, this approach would let Argus
  investigate arbitrary real-world incidents without any hard-coded assumptions about the
  underlying data.
<!--  -->
The core insight — that an LLM can drive a genuine investigation loop, not just generate
a report, and that showing the reasoning is as important as showing the result — holds
regardless of how the supporting infrastructure evolves.
