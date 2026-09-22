# SentinelAI Frontend — Step 1 Architecture Proposal

Status: **proposed for approval**  
Scope: architecture and design system only; no application pages or frontend dependencies have been implemented.

## 1. Guardrails

- The existing Python, SQLite, scikit-learn, and Streamlit implementation remains the reference implementation.
- The frontend is a separate application under `frontend/`.
- The browser never calculates risk, anomaly scores, rule results, feature values, recommendations, or future quantum outputs.
- UI components depend on typed view contracts, not SQLite rows or Python implementation details.
- Demo fixtures are exported from a freshly seeded disposable SentinelAI database. They are never manually invented.
- Missing backend capabilities remain visibly unavailable. They are not approximated in the UI.
- This step does not add Node dependencies, scaffold Next.js, or implement any route.

## 2. Reference implementation audit

### Verified data and workflows

The current service boundary exposes employees, activity rows, detection rows, alert rows, simulation, alert status updates, and investigation notes. The seeded reference dataset contains:

- 30 employees
- 1,356 activity events
- 30 behaviour profiles
- 1,356 detection results
- 195 alerts
- risk distribution: 1,161 Low, 146 Medium, 25 High, 24 Critical
- activity types: login, file access, download, and privilege change
- model state: `ready`

Every detection contains the final risk score, risk level, deterministic rule contribution, Isolation Forest contribution, contextual contribution, rule evidence, explanation, recommended response, anomaly percentile, model status, and the complete 11-value feature vector.

Every rule hit already contains the exact four fields the investigation UI needs: reason code, human-readable reason, observed value, expected value, and contribution.

### Existing terminology to preserve

- Activity Event
- Alert
- Behaviour Profile / Normal Baseline
- Detection Result
- Rule Contribution
- AI nonconformity / anomaly percentile
- Context Contribution
- Triggered Evidence
- Recommended Response
- New, Investigating, Resolved, False Positive

Frontend presentation terminology may use **Threat** for an alert in the queue, but the data contract retains `alertId` and `alertStatus`. The score must always be described as a risk score, never an attack probability.

### Current workflow

1. Dashboard summarizes detections and alerts.
2. Activity Monitor filters events and opens one event's explanation, context, and features.
3. User Behaviour shows a learned profile, risk history, deviations, and activity history.
4. Threat Simulation generates and persists a real synthetic event through the service.
5. Alert Investigation filters alerts, shows evidence/context, updates status, and records notes.

### Live UI observations that shape the redesign

- The reference dashboard is KPI-first; the new overview must be queue-first.
- Streamlit navigation does not provide durable investigation URLs; Next.js routes will make threats and users directly addressable.
- The current alert selector adds a navigation step before evidence. The threat queue should open an investigation directly.
- Five equal-width profile metrics truncate important values at a 1280px workstation width.
- A simulation event dated far beyond the seeded history stretches the risk chart and weakens its analytical value. Chart domains must be explicit and data-backed.
- The current combined threat title comes from the first triggered rule, which can understate a multi-signal story. The frontend must display the persisted title but may also display ordered evidence; it must not generate a replacement story.
- All seeded alerts are `New`. The fixture must preserve that fact rather than manufacture workflow variety.
- There is no incident or chain entity, no server field, and no separately scored asset-sensitivity channel in the current backend.

## 3. Technical architecture

Use a standalone Next.js App Router application with strict TypeScript. Server Components should load route data through a data-source interface. Client Components are reserved for interactions that require browser state: filters, ECharts, React Flow, simulation controls, and restrained Motion transitions.

Official implementation references:

- [Next.js App Router](https://nextjs.org/docs/app)
- [Tailwind CSS with Next.js](https://tailwindcss.com/docs/installation/framework-guides/nextjs)
- [shadcn/ui](https://ui.shadcn.com/docs)
- [React Flow](https://reactflow.dev/learn)
- [Apache ECharts](https://echarts.apache.org/handbook/en/get-started/)
- [Motion for React](https://motion.dev/docs/react)
- [Geist typography](https://vercel.com/geist/typography)

Versions will be selected and locked during Step 2 after compatibility checks. No package version is assumed by this document.

### Proposed directory boundary

```text
frontend/
├── src/
│   ├── app/                      # Route composition only
│   │   ├── page.tsx
│   │   ├── threats/page.tsx
│   │   ├── threats/[id]/page.tsx
│   │   ├── users/[id]/page.tsx
│   │   ├── activity/page.tsx
│   │   ├── attack-lab/page.tsx
│   │   └── models/page.tsx
│   ├── components/
│   │   ├── shell/                # AppShell, navigation, status, search
│   │   ├── threats/              # Queue, rows, evidence, composition, timeline
│   │   ├── users/                # Profile, deviations, risk history
│   │   ├── activity/             # Table and compact filters
│   │   ├── graph/                # React Flow entity graph
│   │   ├── models/               # Model facts and capability states
│   │   ├── feedback/             # Empty, loading, and error states
│   │   └── ui/                   # Selected shadcn primitives, locally themed
│   ├── domain/                   # Stable frontend domain types
│   ├── data/
│   │   ├── sentinel-data-source.ts
│   │   ├── fixture-data-source.ts
│   │   ├── http-data-source.ts   # Added with FastAPI; same interface
│   │   └── fixtures/
│   │       └── sentinel-demo.v1.json
│   ├── design/                   # tokens, semantic styles, formatting rules
│   └── lib/                      # presentation-only formatting and routing
├── scripts/                      # fixture validation/export entry point
└── public/
```

### Dependency policy

Required runtime dependencies are limited to Next.js/React, Tailwind CSS, selected shadcn primitives, `@xyflow/react`, Apache ECharts, Motion for React, and Geist through Next.js font support. A React-specific ECharts wrapper is not required; a small local client component can own the chart lifecycle. Do not install a general state library, data-grid suite, icon mega-pack, date library, or query library unless a concrete Step 2 limitation proves it necessary.

## 4. Application shell

### Structure

- A 52px top bar contains the SentinelAI wordmark, `LIVE` state, system summary, search, and current local operator state.
- A 200–216px left rail contains Overview, Threats, Activity, Users, Attack Lab, and Models.
- A quiet System section shows Model, Database, and Data source state without card chrome.
- Main content uses a dense 12-column grid and an unconstrained workstation canvas with controlled internal column widths.
- The active navigation state uses a low-contrast surface change plus a 2px accent rule; no filled cyan navigation pills.

### Responsive rules

- 1920px: full rail, wide evidence/detail split, persistent contextual right panel.
- 1440px: full rail, 7/5 investigation split.
- 1280px: narrower rail and 8/4 split; secondary metadata wraps below primary evidence before any primary column is truncated.
- Below 1120px: the right investigation panel moves beneath evidence. Threat queue columns reduce in a defined order: department, reason detail, then status metadata. Severity, risk, identity, story, and time remain visible.
- Mobile is functional but is not the primary composition target.

## 5. Centralized design tokens

Tokens will be CSS custom properties consumed by Tailwind and shadcn primitives.

### Color

```css
--color-bg: #080b0e;
--color-surface: #0d1217;
--color-surface-elevated: #111820;
--color-surface-selected: #152028;
--color-border: #1c2730;
--color-border-strong: #2a3944;
--color-text: #edf3f5;
--color-text-muted: #8e9ca6;
--color-text-faint: #63717b;
--color-accent: #35b8aa;
--color-accent-strong: #56cabd;
--color-focus: #73d8ce;
--color-low: #48b883;
--color-medium: #d3a343;
--color-high: #df7d3f;
--color-critical: #dc5656;
```

Accent is reserved for focus, selection, navigation, and neutral system readiness. Low/Medium/High/Critical colors are reserved for security state. Page backgrounds, cards, and charts never use gradients.

### Typography

- Interface: Geist Sans.
- Technical values: Geist Mono for IDs, timestamps, IP addresses, device identifiers, reason codes, scores, and feature names.
- Base: 13px / 20px on workstation tables and controls.
- Page title: 24px / 30px, semibold.
- Section title: 12px / 16px, semibold, uppercase, tracked.
- Numeric emphasis: 18–22px; no oversized KPI typography.
- Tabular numerals are enabled for scores and time.

### Geometry and spacing

- Radius scale: 4px controls, 6px panels, 8px overlays; `999px` only for small semantic status badges.
- Border: 1px structural borders.
- Shadow: none by default; one restrained overlay shadow only for menus/dialogs.
- Spacing scale: 4, 8, 12, 16, 20, 24, 32px.
- Row heights: 36px dense, 44px standard, 52px threat queue.

### Motion

- 120ms selection/focus transition.
- 160ms row or panel state change.
- 220ms route/timeline reveal maximum.
- Opacity and small positional changes only; no looping, background, or ornamental motion.
- `prefers-reduced-motion` removes nonessential transitions.

## 6. Component architecture

### Shell and system

- `AppShell`: owns persistent top bar, rail, content landmarks, skip link, and responsive layout.
- `SystemStatus`: renders model/database/data-source states from typed facts.
- `CompactStat`: one short value/label pair with no card requirement.

### Threat workflow

- `ThreatQueue`: accessible sortable list/table; owns no risk logic.
- `ThreatRow`: navigates to `/threats/[id]`; preserves severity, score, identity, title, primary persisted evidence, timestamp, and status.
- `ThreatSeverity`: semantic text + color marker; never color alone.
- `RiskValue`: displays a supplied score and risk level; performs formatting only.
- `EventTimeline` / `EventTimelineItem`: accepts an ordered event array. One real event renders as one item with no implied missing steps.
- `EvidenceRow`: reason code, reason, observed, expected, contribution.
- `RiskComposition`: displays supplied channels. Unsupported channels render `NOT AVAILABLE`, not zero.

### Identity and telemetry

- `UserProfile`: identity and learned baseline facts.
- `DeviationRow`: direct supplied observed-versus-expected comparison.
- `ActivityTable`: dense sortable telemetry with route navigation.
- `FilterBar`: compact query controls; controls URL search parameters where practical.

### Investigation graph and feedback

- `EntityGraph`: React Flow view with deterministic layout, keyboard selection, connected-node focus, contextual detail, and related event list.
- `EmptyState`, `LoadingState`, `ErrorState`: consistent page and region feedback without illustrations.

Page components compose these units and request data. They do not reshape persistence records or calculate security values.

## 7. Typed domain contract

```ts
export type RiskLevel = "Low" | "Medium" | "High" | "Critical";
export type AlertStatus = "New" | "Investigating" | "Resolved" | "False Positive";
export type ModelAvailability = "ready" | "untrained" | "insufficient_training_data" | "not_implemented";

export interface Evidence {
  code: string;
  reason: string;
  observed: string;
  expected: string;
  contribution: number;
}

export interface RiskChannel {
  key: "rule" | "classicalAnomaly" | "context" | "assetSensitivity" | "quantumAnomaly";
  label: string;
  value: number | null;
  availability: "available" | "not_separately_scored" | "not_implemented";
  source: string;
}

export interface ActivityEvent {
  eventId: string;
  employeeId: string;
  occurredAt: string;
  activityType: "login" | "file_access" | "download" | "privilege_change";
  scenario: string;
  deviceId: string;
  ipAddress: string;
  city: string;
  country: string;
  resourceName: string | null;
  resourceSensitivity: string;
  previousPrivilege: string;
  currentPrivilege: string;
  downloadCount: number;
  downloadSizeMb: number;
}

export interface Detection {
  detectionId: string;
  eventId: string;
  detectedAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  channels: RiskChannel[];
  anomalyPercentile: number | null;
  modelStatus: ModelAvailability;
  evidence: Evidence[];
  explanation: string;
  recommendedResponse: string;
  featureValues: Record<string, number>;
}

export interface ThreatSummary {
  alertId: string;
  eventId: string;
  employeeId: string;
  employeeName: string;
  department: string;
  title: string;
  riskScore: number;
  riskLevel: RiskLevel;
  primaryEvidence: Evidence | null;
  occurredAt: string;
  createdAt: string;
  status: AlertStatus;
}

export interface ThreatInvestigation {
  threat: ThreatSummary;
  employee: EmployeeIdentity;
  timeline: ActivityEvent[];
  detection: Detection;
  notes: InvestigationNote[];
  graph: InvestigationGraph;
}

export interface BehaviourProfile {
  employeeId: string;
  normalLoginStart: number;
  normalLoginEnd: number;
  usualCountries: string[];
  usualCities: string[];
  knownDevices: string[];
  averageDownloadCount: number;
  averageDownloadSizeMb: number;
  typicalFileSensitivity: string[];
  normalPrivilege: string;
  averageFailedLoginCount: number;
  historyEventCount: number;
  confidence: number;
}

export interface ModelDescriptor {
  name: "Isolation Forest" | "Quantum Kernel";
  status: ModelAvailability;
  version: string | null;
  featureSchemaVersion: string | null;
  featureOrder: string[];
  trainingRows: number | null;
  trainingScope: string | null;
  anomalyDefinition: string | null;
}
```

`EmployeeIdentity`, `InvestigationNote`, query/page contracts, chart-series DTOs, simulation DTOs, and graph node/edge unions follow the same rule: transport already-computed facts, never security calculations.

## 8. Data-source interface

```ts
export interface SentinelDataSource {
  getSystemStatus(): Promise<SystemStatusSnapshot>;
  getOverview(): Promise<OperationsOverview>;
  listThreats(query: ThreatQuery): Promise<Page<ThreatSummary>>;
  getThreat(alertId: string): Promise<ThreatInvestigation | null>;
  listUsers(query: UserQuery): Promise<Page<EmployeeIdentity>>;
  getUser(employeeId: string): Promise<UserInvestigation | null>;
  listActivity(query: ActivityQuery): Promise<Page<ActivityRecord>>;
  listSimulationOptions(): Promise<SimulationOptions>;
  runSimulation(input: SimulationInput): Promise<SimulationResult>;
  getModels(): Promise<ModelDescriptor[]>;
}
```

`FixtureDataSource` reads versioned local JSON. A future `HttpDataSource` calls FastAPI and returns the same domain contracts. Components receive a `SentinelDataSource` through a server-side composition function, so changing the backend does not change page or component props.

Filtering, sorting, pagination, and display formatting are allowed in the frontend. Risk classification, anomaly conversion, evidence generation, recommendations, and contribution fusion are forbidden.

## 9. Deterministic fixture schema

The approved implementation step should add a Python exporter that initializes a disposable database with seed 42 and serializes persisted service output. Proposed output: `frontend/src/data/fixtures/sentinel-demo.v1.json`.

```ts
export interface SentinelDemoFixtureV1 {
  fixture: {
    schemaVersion: "sentinel-demo.v1";
    source: "sentinelai-python-reference";
    classification: "development_demo_data";
    randomSeed: 42;
    generatedAt: string;
    counts: {
      employees: 30;
      activityEvents: 1356;
      detections: 1356;
      alerts: 195;
    };
  };
  system: SystemStatusSnapshot;
  overview: OperationsOverview;
  employees: EmployeeIdentity[];
  profiles: BehaviourProfile[];
  activity: ActivityRecord[];
  threats: ThreatInvestigation[];
  simulations: SimulationOptions;
  models: ModelDescriptor[];
}
```

The exporter, not the browser, creates joined DTOs and analytical series. The export is deterministic except for an informational `generatedAt` value, which is excluded from snapshot comparisons. Fixture validation must assert referential integrity, exact counts, recognized enums, score range, risk/channel equality with persisted values, and the absence of quantum values.

### Actual reference values available to the fixture

- Overview state: 24 Critical, 25 High, 146 Medium alerts; model ready.
- Isolation Forest: `iforest-v1`, feature schema `behavior-features-v1`, random seed 42, 200 estimators, trained on 360 normal-history feature rows.
- Feature order: login-hour deviation, outside working hours, unknown device, location anomaly, failed login count, download-count deviation, download-size deviation, sensitive file, privilege escalation, travel speed, impossible travel.
- EMP-001 is Asha Rao, Engineering, Bangalore, normal login 09:39–18:50, two known devices, 7.33 average downloads, 18.97 MB average file size, Manager privilege, 28 baseline events, confidence 0.933.
- Critical reference alert `ALT-EVT-001332` is a real persisted combined-compromise result for EMP-018 with risk 100, rule contribution 164, classical anomaly contribution 25, context contribution 15, and nine structured rule hits.

These values are evidence for the schema, not hand-authored UI content. The eventual fixture must be generated directly from the disposable database.

## 10. Investigation graph contract

Supported node types are `user`, `device`, `ip`, `location`, `role`, `resource`, and `server`. Supported relationship labels are `connected_from`, `accessed`, `assigned`, `downloaded`, and `logged_into`.

For current data:

- user, device, IP, location, role, and resource nodes can be derived directly from persisted events;
- `connected_from` links the user to observed device/IP/location entities;
- `assigned` links the user to the observed role;
- `accessed` or `downloaded` links the user to a real resource;
- server nodes and `logged_into` edges are omitted because the current model has no server field.

Selecting a node highlights only directly connected nodes/edges, opens factual context, and lists related real event IDs. Layout is deterministic and static after load; there is no decorative motion.

## 11. Route responsibilities

- `/`: threat queue first, compact severity counts, then risk and anomaly activity series supplied by the data source.
- `/threats`: filterable and sortable threat queue.
- `/threats/[id]`: single threat workstation with real timeline, evidence, composition, recommendation, graph, and workflow history.
- `/users/[id]`: identity dossier, baseline, supplied deviations, risk series, and dense event history.
- `/activity`: telemetry table with URL-backed filters and navigation to related threat/user routes.
- `/attack-lab`: visibly isolated synthetic environment; runs only through the data source.
- `/models`: actual Isolation Forest metadata plus Quantum Kernel `NOT IMPLEMENTED`.

The global Users navigation opens a compact user finder; choosing a real employee routes to `/users/[id]`. No separate `/users` route is required by the current information architecture.

## 12. Accessibility and verification contract

- Semantic landmarks, headings, tables, buttons, and links before custom interaction patterns.
- Full keyboard access for queue rows, filters, evidence tabs, and graph node selection.
- Visible focus using the focus token; no color-only severity or status communication.
- Screen-reader labels include risk level and score.
- ECharts receives text summaries and tabular equivalents for its analytical series.
- React Flow nodes expose entity type, label, selected state, and relationship context.
- Minimum target size 32px for dense workstation controls; primary actions 36px or greater.
- Contrast is checked at both default and muted text levels.
- Reduced-motion behavior is tested.

After each implementation step: typecheck, lint, production build, dev-server startup, browser verification at 1280/1440/1920 widths, screenshots, keyboard review, and rendered anti-slop review.

## 13. Graph-Based Security Analysis

### Detection pipeline position

```
Classical + Quantum Analysis
          ↓
    Sequence Analysis
          +
     Graph Analysis (supplementary)
          ↓
       Risk Engine
```

Graph analysis provides supplementary explainable evidence. It does **not** modify production risk scores in this milestone. A configuration flag `ENABLE_GRAPH_RISK_CONTRIBUTION = False` is present and disabled.

### Graph node types

| Type | Source | ID format |
|------|--------|-----------|
| `employee` | `employees` table | `employee:{employee_id}` |
| `device` | Event `device_id` field | `device:{device_id}` |
| `ip_address` | Event `ip_address` field | `ip_address:{ip}` |
| `location` | Event `city`, `country` fields | `location:{city}, {country}` |
| `file` | Event `file_name` (Confidential/Restricted only) | `file:{file_name}` |
| `department` | Employee `department` field | `department:{department}` |
| `attack_run` | `simulation_runs` table | `attack_run:{simulation_id}` |

### Relationship edge types

| Edge type | Source → Target | Derived from |
|-----------|----------------|--------------|
| `USES_DEVICE` | employee → device | Activity event `device_id` |
| `CONNECTS_FROM` | employee → ip_address | Activity event `ip_address` |
| `LOGS_IN_FROM` | employee → location | Activity event `city`, `country` |
| `ACCESSES_FILE` | employee → file | Activity event `file_name` |
| `BELONGS_TO` | employee → department | Employee `department` |
| `PART_OF_ATTACK_RUN` | event → attack_run | `simulation_events` table |
| `ASSOCIATED_WITH_ATTACK` | employee → attack_run | `simulation_runs` table |

### Graph finding rules

| Finding type | Trigger condition | Severity logic |
|-------------|-------------------|----------------|
| `SHARED_DEVICE` | Device used by ≥2 employees with medium+ risk events | `high` if High/Critical events; `medium` if Medium; else `informational` |
| `SHARED_IP` | IP shared by ≥3 employees with high-risk events | `critical` if ≥3 H/C events; `high` if any; `medium` if multiple medium |
| `MULTI_USER_SUSPICIOUS_INFRASTRUCTURE` | Same device+IP used by multiple employees in high-risk events within time window | `critical` if Critical event; else `high` |
| `SENSITIVE_FILE_CONVERGENCE` | Multiple employees access same Confidential/Restricted file within time window | `high` if ≥3 employees; else `medium` |
| `ATTACK_INFRASTRUCTURE_CLUSTER` | Attack run infrastructure appears in other suspicious events | `high` |
| `HIGH_RISK_ENTITY` | Entity has ≥50% High/Critical events (min 3 total) | `critical` if ≥80%; else `high` |

### Time window configuration

All temporal thresholds are centralized in `src/sentinel_ai/config.py`:

- `GRAPH_SHARED_ENTITY_WINDOW_MINUTES = 60`
- `GRAPH_FILE_CONVERGENCE_WINDOW_MINUTES = 15`
- `GRAPH_SHARED_DEVICE_MIN_EMPLOYEES = 2`
- `GRAPH_SHARED_IP_MIN_EMPLOYEES = 3`
- `GRAPH_HIGH_RISK_EVENT_RATIO_THRESHOLD = 0.5`

### Why graph findings do not yet change production risk

Graph analysis is supplementary in this milestone to:
1. Allow analysts to evaluate graph-based evidence quality before trusting it for automation.
2. Avoid changing the 10 validated regression risk scores.
3. Build confidence in graph finding accuracy over real-world data.
4. Future milestone will introduce `ENABLE_GRAPH_RISK_CONTRIBUTION = True` with weighted graph evidence contribution to the hybrid risk score.

### Graph API endpoints

| Method | Path | Response |
|--------|------|----------|
| GET | `/api/graph/overview` | `GraphOverviewDto` — node/edge counts, entity breakdown, all findings |
| GET | `/api/graph/entities/{type}/{id}` | `GraphEntityDetailDto` — entity + neighbors + findings |
| GET | `/api/graph/events/{event_id}` | `GraphEventContextDto` — entities + findings for event |
| GET | `/api/graph/attack-runs/{sim_id}` | `GraphAttackRunContextDto` — categorized connected entities |
| GET | `/api/graph/findings` | `GraphFindingsPageDto` — filtered, paginated findings |

All endpoints follow existing API conventions: camelCase wire format, `ApiModel` base class, standard error envelope.

### Graph UI

The `/graph` page contains:
1. **Summary cards** — total entities, relationships, shared devices, shared IPs, high-risk findings.
2. **Interactive visualization** — ECharts Graph Series with force layout, zoom/pan, node selection, adjacency highlighting, and tooltips.
3. **Findings table** — severity badges, entity lists, explanations.
4. **Entity detail panel** — contextual panel on node selection showing metadata and connections.

Integration points:
- Activity table shows device/IP/location badges inline.
- User detail page shows "Relationship Context" section with derived device/IP/location/file summaries.
- Attack Lab run detail shows connected infrastructure context.

## 14. Step 2 approval boundary

If this proposal is approved, Step 2 will scaffold the frontend, pin compatible dependencies, implement only the centralized tokens, AppShell, Overview, and Threat Queue, generate the initial fixture through the Python reference implementation, and run the complete quality gate.

Threat Investigation, User Investigation, Activity, Attack Lab, Entity Graph, and Models remain out of scope until their scheduled steps.
