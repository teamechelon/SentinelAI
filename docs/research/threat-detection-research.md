# SentinelAI – Technical Research for an Explainable Behavioural Threat-Detection Prototype

**Research date:** 2026-09-22  
**Target stack:** Python, Streamlit, SQLite, scikit-learn  
**Project level:** college prototype using a small, deterministic synthetic dataset

## How to read this report

- **Verified finding** means the statement follows from an official specification, product/API documentation, an original research paper, or an authoritative cybersecurity source linked inline.
- **Project recommendation** means a design choice proposed for SentinelAI. Numeric windows, weights, and thresholds in this report are starting hypotheses, not externally validated security constants.
- An anomaly score in this design is a **ranking/deviation score, not a probability that an event is malicious**. Scikit-learn's outlier estimators expose decision or sample scores and thresholded labels; they do not make those scores calibrated incident probabilities ([scikit-learn outlier-detection guide](https://scikit-learn.org/stable/modules/outlier_detection.html)).

## Executive summary

The most suitable MVP is a **hybrid detector**:

1. deterministic rules for security facts that already have clear meaning, such as an unknown device, a failed-login burst, an access to a file marked sensitive, an administrative group change, or impossible travel;
2. personal and peer behavioural baselines;
3. one global `IsolationForest`, trained on compact numeric **behaviour-window and baseline-deviation features** rather than raw event identifiers;
4. a small sequence correlator for multi-step stories; and
5. an explicit, deterministic risk formula with a complete contribution ledger.

This approach fits a small synthetic dataset better than training one model per person. Isolation Forest directly isolates observations through random feature/split partitions; anomalies tend to require shorter paths ([Liu, Ting & Zhou, 2008](https://doi.org/10.1109/ICDM.2008.17); [scikit-learn API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)). It handles nonlinear combinations, is inexpensive for a local demo, accepts a fixed `random_state` for repeatability, and does not require the large representation-learning exercise introduced by an autoencoder. It should still be compared empirically with scaled One-Class SVM and LOF baselines because scikit-learn explicitly notes that different outlier estimators perform differently across datasets and hyperparameters ([official benchmark example](https://scikit-learn.org/stable/auto_examples/miscellaneous/plot_outlier_detection_bench.html)).

The final risk score should be a transparent fusion such as:

\[
\text{risk} = \operatorname{round}(0.45A + 0.40R + 0.15S)
\]

where `A` is an empirical percentile of the model's nonconformity score on a held-out benign calibration period, `R` is a capped sum of documented rule weights, and `S` is a deterministic multi-event sequence score. The percentile puts scores from a particular model/version on a readable 0–100 rank scale; it **does not** turn them into probabilities.

Every alert should show the raw model score, calibration percentile, baseline confidence, observed-versus-expected values, each triggered rule and weight, the sequence evidence, the model/version status, and the exact arithmetic that produced the total. This meets the spirit of NIST's explainability principles: provide reasons, make them meaningful, ensure they accurately reflect the process, and disclose knowledge limits ([NISTIR 8312](https://doi.org/10.6028/NIST.IR.8312)).

### Essential scope correction

Despite the name “Network Threat Detection System,” the requested detections are primarily **user and entity behaviour analytics (UEBA)** over identity, device, privilege, and file-audit events. They are not packet- or flow-level network intrusion detection. Windows, for example, records successful/failed logons as 4624/4625, object access as 4663, special privileges on a new logon as 4672, and security-group membership changes in events such as 4728/4732 ([Microsoft audit-event reference](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference); [event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663); [advanced audit policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)). SentinelAI should be described as a **behavioural identity-and-file threat detector** unless packet/flow telemetry is added later. CICIDS2017 and UNSW-NB15 are useful for a future true NIDS extension, but they do not validate the present UEBA claims.

## Recommended approach

### Direct answers to the 12 research questions

1. **Best anomaly algorithm for a small synthetic dataset:** use `IsolationForest` as the primary anomaly ranker, with a fixed seed and a small numeric feature set. Keep deterministic rules first-class rather than expecting the model to rediscover them.
2. **Isolation Forest vs alternatives:** benchmark scaled One-Class SVM and LOF, but do not make them the default. Defer an autoencoder until substantially more representative normal history exists and its added value is measured. Include a robust statistical baseline (median/MAD or quantile rule) to verify the ML model earns its complexity.
3. **Behaviour baselines:** maintain prior-only personal profiles and role/department peer profiles, then blend them according to the user's history count. Train one global model on deviations from those profiles, not a fragile per-user model.
4. **Features:** extract circular local time, day type, device/location/resource novelty, recent fail counts, geodesic distance and required travel speed, access/download volumes over several trailing windows, resource sensitivity, privilege changes, and cross-event sequence features. Never feed raw `user_id` or high-cardinality file paths directly to the model.
5. **Score fusion:** normalize model nonconformity using an empirical benign calibration distribution; combine it with documented rules and sequence scores through fixed arithmetic. Never label the result a probability.
6. **Understandable alerts:** emit stable reason codes with observed value, expected baseline, threshold, contribution, evidence-event IDs, and confidence/status. Treat observed deviations as evidence, not as an unsupported claim that they are the tree model's causal feature attribution.
7. **Impossible travel:** order successful logins per user in UTC, compute great-circle distance between consecutive reliable coordinates, subtract geolocation uncertainty, divide by elapsed time, and compare the required speed with a configurable policy threshold. Suppress or downgrade known VPN/proxy/office-egress cases.
8. **Cold start:** fall back to the peer then global baseline; blend in personal history gradually; expose a baseline-confidence field; and rely more on high-confidence rules until history is sufficient.
9. **False positives:** use context-aware rules, prior-only baselines, peer fallbacks, trusted-network and maintenance suppressions, multi-signal correlation, per-scenario thresholds, alert grouping, reviewed-benign retraining, and threshold selection based on false alerts per user-day.
10. **Public datasets:** start with the CMU SEI CERT Insider Threat Test Dataset; later use LANL authentication/host data for authentication-scale experiments. Use CICIDS2017 or UNSW-NB15 only for a separately defined network-flow module.
11. **Metrics:** make precision-recall/Average Precision, recall, precision, false positives per user-day, scenario-detection rate, and time-to-detect primary. Report ROC-AUC only as a secondary ranking metric. Split chronologically and also run a user-disjoint cold-start evaluation.
12. **Architecture:** a single local Streamlit process calling modular Python services and repositories over SQLite is enough. Separate normalization, feature calculation, baselines, models, rules, sequences, risk, explanations, and storage behind interfaces; persist complete evidence and version metadata.

### Recommended detection pipeline

```text
Synthetic event scenarios / imported audit CSV
                    |
                    v
        validation + normalization (UTC)
                    |
                    v
       immutable normalized event store
                    |
        +-----------+------------+
        |                        |
        v                        v
 trailing feature windows   deterministic rules
        |                        |
        v                        |
 personal + peer baseline       |
        |                        |
        v                        |
 Isolation Forest score         |
        +-----------+------------+
                    v
          sequence correlation
                    |
                    v
       deterministic risk + reasons
                    |
                    v
        persisted alert / Streamlit UI
```

NIST describes anomaly detection as comparing observed activity with profiles of normal users, hosts, connections, or applications; those profiles are built by observing typical activity over time ([NIST SP 800-94, section 2.3.2](https://doi.org/10.6028/NIST.SP.800-94)). That supports the overall baseline/deviation structure. The exact feature windows and blending method below are SentinelAI recommendations.

## Algorithm comparison

| Method | Verified characteristics | Fit for this MVP | Main cautions | Recommendation |
|---|---|---|---|---|
| **Isolation Forest** | Randomly selects features and split values; anomalies have shorter average isolation paths ([original paper](https://doi.org/10.1109/ICDM.2008.17); [API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)). `contamination` affects the fitted decision threshold, while scores remain model-specific. | Strong: fast, nonlinear, straightforward on compact tabular windows, deterministic with a seed. | A score is not a probability; rare-but-benign activity will be anomalous; explanations are not inherently per-feature; training contamination can normalize bad activity. | **Primary model.** Fit a global model on clean/mostly benign historical windows and calibrate thresholds separately. |
| **One-Class SVM (RBF)** | Estimates the support of a high-dimensional distribution ([Schölkopf et al., 2001](https://research.google/pubs/estimating-the-support-of-a-high-dimensional-distribution/)). `nu` bounds training errors/support vectors and `gamma` controls the kernel ([API](https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html)). | Reasonable benchmark when the dataset is genuinely small and normal behaviour forms a smooth boundary. | Sensitive to kernel/`nu`/`gamma`, training outliers, and feature scale. Scikit-learn notes One-Class SVM is sensitive to outliers; RBF distances make scaling material ([outlier guide](https://scikit-learn.org/stable/modules/outlier_detection.html); [StandardScaler](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html)). | **Secondary benchmark.** Use a `Pipeline` with robust/standard scaling fitted on training data only; tune on validation scenarios. |
| **Local Outlier Factor (LOF)** | Compares a point's local density with its neighbours ([Breunig et al., 2000](https://doi.org/10.1145/335191.335388); [API](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html)). | Useful if legitimate users form several clusters of different density and attacks are local deviations. | Distance is affected by scaling and encoding. Default `novelty=False` is transductive; for live unseen events use `novelty=True`, and then call `predict`, `decision_function`, or `score_samples` **only on unseen data**, not the training set ([official novelty example](https://scikit-learn.org/stable/auto_examples/neighbors/plot_lof_novelty_detection.html)). | **Benchmark only.** Easy to misuse in streaming scoring; validate `n_neighbors` and latency. |
| **Autoencoder** | A multilayer encoder/decoder can learn a low-dimensional representation by reconstructing input ([Hinton & Salakhutdinov, 2006](https://doi.org/10.1126/science.1127647)). Reconstruction error then requires a separately chosen alert threshold. | Weak for the initial project: the data are small, tabular, mixed, and synthetic, while a neural model adds architecture, optimization, regularization, and reproducibility choices. | With limited normal examples, excess capacity may memorize data or reconstruct anomalies; too little capacity can flag normal variation. Explaining a reconstruction error faithfully is harder. Deep anomaly methods are intended to learn representation from complex data and introduce assumptions beyond shallow detectors ([Ruff et al., 2021](https://doi.org/10.1109/JPROC.2021.3052449)). | **Defer.** Reconsider only after a learning curve shows enough representative history and a held-out benchmark demonstrates clear benefit. “Needs more data” is a project risk assessment, not a universal theorem. |
| **Robust univariate/multivariate statistics** | Scikit-learn's `EllipticEnvelope` fits a robust covariance ellipse but assumes approximately Gaussian inlier data ([outlier guide](https://scikit-learn.org/stable/modules/outlier_detection.html)). Median/MAD and empirical quantiles do not require that full multivariate Gaussian model. | Excellent transparent baseline for counts, bytes, and time deviations. | Misses nonlinear feature interactions; covariance methods are a poor match for mixed/multimodal behaviour. | **Required sanity baseline.** Keep explicit quantile/MAD rules beside the ML model. |
| **Supervised classifier** | Requires representative labels for the target distribution. The synthetic generator can provide labels, but those labels may reveal generator-specific shortcuts. | Potentially high apparent accuracy, but inappropriate as the main “learn normal behaviour” claim with a tiny synthetic corpus. | Severe overfitting and leakage risk; cannot justify generalization to real attacks. | **Not the MVP detector.** Use labels for evaluation and threshold selection, not to overclaim supervised real-world performance. |

### Why Isolation Forest is the recommended default

The recommendation is conditional, not a statement that Isolation Forest is universally best. Its practical advantages here are:

- compact local CPU/memory use;
- no neural training loop;
- no pairwise neighbourhood search at every prediction;
- nonlinear interactions among behavioural deviations;
- stable demo output with a fixed seed; and
- an established scikit-learn interface for `fit`, `score_samples`, `decision_function`, and `predict` ([official API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)).

For a small dataset, set `max_samples` no larger than available training rows, use roughly 100–300 trees as a prototype range, and fix `random_state`. Do **not** set a business alert threshold merely by guessing `contamination`. Learn the operational threshold from a separate, chronologically later calibration/validation period and report the achieved alert workload.

### Preprocessing and leakage controls

- Represent high-cardinality categories as behavioural facts (`is_new_device`, `device_seen_count`, `resource_peer_frequency`) rather than raw IDs.
- Scale continuous features for One-Class SVM and LOF. Tree-based Isolation Forest is much less dependent on scale, though feature engineering still determines meaning.
- Put preprocessing and the estimator in a scikit-learn `Pipeline`; pipelines help keep transformers fitted only on training data and prevent test-statistic leakage ([scikit-learn pipeline guide](https://scikit-learn.org/stable/modules/compose.html); [data-leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html)).
- Fit encoders, scalers, personal/peer profiles, score normalization, thresholds, and rule tuning on training/calibration data only—never the final test period.

## User behavioural baselines

### Recommended baseline hierarchy

Use one event-time-correct hierarchy:

1. **Personal baseline** for the same user, based only on events before the event being scored.
2. **Peer baseline** for users with the same stable role/department/work pattern.
3. **Global baseline** when a peer group is too small or missing.

Do not train a separate Isolation Forest per user for the MVP. A small dataset will leave those models underdetermined. Instead, convert raw activity into features such as “login-hour rarity for this user,” “download bytes / personal 95th percentile,” and “resource-access rarity among peers,” then train a single global model over these comparable deviation features.

### Profile contents

For each user and peer group, store versioned, trailing summaries:

- event count and number of active days;
- hour-of-week histogram or circular-time centroid/dispersion;
- working-day/weekend rate;
- known devices and first/last seen times;
- country/region/office-network frequencies;
- median, MAD, and upper quantiles for login/file counts and bytes in 15-minute, 1-hour, and 24-hour windows;
- file/resource category frequencies and sensitivity distribution;
- normal privilege level and administrative-action frequency; and
- usual login-to-file-access sequences and transition counts.

Use robust summaries because a few injected attacks should not move a mean/standard deviation dramatically. Update profiles only from reviewed-benign events or a delayed clean batch. NIST warns that dynamic profiles can absorb slowly changing malicious activity and that malicious activity can enter initial training profiles ([NIST SP 800-94](https://doi.org/10.6028/NIST.SP.800-94)); therefore, unrestricted online self-training is out of scope for the MVP.

### Cold-start blending

Let `n` be the user's number of eligible historical windows and `k` a configurable transition size (for example, 20 windows in the demo). For any numeric expectation:

\[
w_u = \frac{n}{n+k}, \qquad
\text{baseline} = w_u\,\text{personal} + (1-w_u)\,\text{peer/global}
\]

Expose `w_u` as `baseline_confidence`; do not hide it. For categorical novelty, require enough prior observations before saying “new for this user”; otherwise say “not seen in limited history” and compare against peers. High-confidence rules—sensitive-file access, an actual group-membership change, or a failed-login burst—remain usable during cold start. This shrinkage formula and the proposed `k` are project recommendations and must be validated.

### Time and drift

- Store timestamps in UTC and derive local time from the user's configured home/working timezone.
- Encode time cyclically (`sin`/`cos`) or use hour-of-week frequencies so 23:59 and 00:01 remain close.
- Use a rolling history (prototype candidate: last 30 active days) plus a stable long-term reference.
- Detect drift by tracking score/rule rates and baseline distributions. Retraining should be a deliberate, logged action, not a response to every new alert.

## Proposed features

Microsoft's audit documentation shows that logon records contain account, logon type, workstation/source address and authentication information, while object-access event 4663 contains account, object name, process and requested access rights ([logon auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon); [event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)). These are examples of real fields that the synthetic schema can mirror. The following transformations are recommendations.

### Normalized source fields

Every event should have:

`event_id`, `event_time_utc`, `ingested_at_utc`, `event_type`, `user_id`, `source_ip`, `device_id`, `result`, `auth_method`, `latitude`, `longitude`, `geo_accuracy_km`, `resource_id`, `resource_category`, `sensitivity`, `operation`, `bytes`, `old_privilege`, `new_privilege`, and `scenario_label` (labels available only to the evaluator, never feature generation).

Keep user/device/resource identifiers for joins and evidence, not as direct numeric model inputs.

### Login and identity features

| Feature | Calculation / purpose | Primary detector |
|---|---|---|
| `local_hour_sin`, `local_hour_cos` | Circular encoding of user's local hour. | ML + baseline |
| `hour_of_week_rarity` | `1 - personal frequency` for that hour bucket, falling back to peer frequency. | ML + reason |
| `is_weekend`, `is_configured_off_hours` | Explicit policy context. | Rule + ML |
| `minutes_since_previous_success` | Time from prior successful login for the user. | ML / travel |
| `failed_5m`, `failed_15m`, `failed_60m` | Prior-only failed-login counts by user and optionally source IP. MITRE maps repeated password attempts to Brute Force T1110 ([MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)). | Rule + ML |
| `fail_then_success` | Successful login shortly after a burst of failures. | Sequence |
| `device_seen_before`, `device_age_days`, `device_user_count` | Device novelty and whether the device is shared. | Rule + ML |
| `country_seen_before`, `location_frequency`, `distance_from_usual_km` | Geographic novelty relative to reliable prior locations. | Rule + ML |
| `travel_distance_km`, `travel_elapsed_hours`, `required_speed_kmh` | Consecutive-login travel features; see calculation below. | Rule + ML |
| `geo_reliability` | Derived from missing data, accuracy radius, private IP, VPN/proxy/office egress. | Rule gating |
| `auth_method_new`, `logon_type_new` | Authentication/logon-mode novelty. | ML + reason |
| `concurrent_session_count` | Other active sessions for the user. | ML / sequence |
| `is_privileged_account`, `privilege_changed`, `privilege_delta` | Account context and change magnitude. Special privileges and group changes have explicit audit events ([event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672); [Microsoft audit policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)). | Rule + sequence |

### File and data-access features

| Feature | Calculation / purpose | Primary detector |
|---|---|---|
| `file_ops_15m`, `file_ops_1h`, `file_ops_24h` | Read/write/download/delete counts over trailing windows. | ML + rule |
| `bytes_15m`, `bytes_1h`, `bytes_24h` | Total prior/current transfer volume; log-transform for modeling. | ML + rule |
| `distinct_files_1h`, `distinct_dirs_1h` | Breadth of access. | ML |
| `download_vs_personal_p95`, `download_vs_peer_p95` | Ratio to robust personal and peer thresholds. | ML + reason |
| `resource_seen_before`, `resource_personal_frequency` | Personal novelty. | ML + reason |
| `resource_peer_frequency` | Rarity for role/department peers. | ML + reason |
| `cross_department_resource` | Whether resource ownership conflicts with the user's peer group. | Rule + ML |
| `sensitivity_level`, `is_sensitive` | Classification supplied by the synthetic catalog, not inferred by the model. | Rule + reason |
| `operation_type` | Read, download, write, delete, permission change. | Rule + ML |
| `new_process_for_file_access` | Optional process novelty if host audit data includes it. Event 4663 exposes process and access-right fields ([Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)). | ML + reason |
| `minutes_since_privilege_change` | Links access with recent elevation. | Sequence |
| `sensitive_bytes_after_elevation` | Sensitive volume following privilege escalation. | Sequence / rule |

### Sequence features

The MVP should recognize a few deterministic, time-bounded patterns rather than attempt a learned sequence model:

- many failures → successful login from a new device/location;
- new-country login → sensitive-file access;
- privilege increase → new sensitive resource → bulk download;
- unusual off-hours login → broad file enumeration → downloads;
- concurrent distant sessions → sensitive activity.

Each match should retain the ordered evidence-event IDs and permitted maximum gaps. MITRE notes that compromised valid accounts can support initial access, persistence, privilege escalation, or defense evasion ([Valid Accounts T1078](https://attack.mitre.org/techniques/T1078/)); local and shared resources may be collected before exfiltration ([Data from Local System T1005](https://attack.mitre.org/techniques/T1005/); [Network Shared Drive T1039](https://attack.mitre.org/techniques/T1039/)). ATT&CK mappings describe plausible technique context, not proof of attacker intent.

## Impossible-travel calculation

Microsoft defines impossible travel as the same user appearing in two locations in less time than expected travel would require, while noting VPNs and trusted/safe IPs as important false-positive conditions ([Defender policy documentation](https://learn.microsoft.com/en-us/defender-cloud-apps/policies-threat-protection); [alert investigation guidance](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-alerts)). IP geolocation is inherently imprecise and may locate a VPN server rather than the end user; a provider-supplied accuracy radius must therefore be retained ([MaxMind accuracy guidance](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy); [developer documentation](https://dev.maxmind.com/geoip/docs/web-services/)).

### Recommended deterministic algorithm

For every **successful** login, find the immediately preceding successful login for the same human user. Ignore service accounts and non-geolocatable/private source IPs.

Given latitudes `φ1, φ2` and longitudes `λ1, λ2` in radians, calculate spherical great-circle distance:

\[
a=\sin^2\left(\frac{\phi_2-\phi_1}{2}\right)
  +\cos(\phi_1)\cos(\phi_2)
   \sin^2\left(\frac{\lambda_2-\lambda_1}{2}\right)
\]

\[
d=2R\operatorname{atan2}(\sqrt{a},\sqrt{1-a})
\]

Use `R = 6371.008 km` for the demo and test edge cases around the date line. A spherical calculation returns distance between longitude/latitude points and is faster but less accurate than a spheroidal calculation; this trade-off is documented by PostGIS ([`ST_DistanceSphere`](https://postgis.net/docs/ST_DistanceSphere.html); [`ST_Distance`](https://postgis.net/docs/ST_Distance.html)). For login-risk screening, geolocation uncertainty normally dominates the small spherical-versus-spheroidal difference.

With provider accuracy radii `r1` and `r2`:

\[
d_{effective}=\max(0,d-r_1-r_2),\quad
\Delta t=(t_2-t_1)/3600,\quad
v_{required}=d_{effective}/\Delta t
\]

Flag `IMPOSSIBLE_TRAVEL` only if all are true:

1. timestamps are valid and `Δt > 0`;
2. `d_effective` exceeds a minimum distance;
3. `v_required` exceeds a configurable maximum plausible speed;
4. both locations meet minimum reliability; and
5. neither event belongs to a trusted VPN, corporate egress, known proxy, or approved travel exception.

For a deterministic demo, prototype starting values such as `minimum_distance_km = 300` and `maximum_speed_kmh = 900`, but label them as project policy and validate them; there is no universal authoritative threshold. If `Δt <= 0`, emit `TRAVEL_TIME_INVALID` as data-quality evidence instead of dividing. Store both locations, radii, distance, elapsed time, speed, threshold, and suppression decision in the alert.

## Risk-scoring design

### 1. AI component `A`: readable rank, not probability

For Isolation Forest, lower `decision_function` values are more abnormal and zero is the estimator's threshold after applying its offset ([API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)). Define nonconformity `q(x) = -decision_function(x)`.

On a **held-out benign calibration period** with nonconformities `q1…qn`, define:

\[
A(x)=100\times\frac{\#\{i:q_i\le q(x)\}}{n}
\]

This empirical percentile makes “more unusual than 98% of benign calibration windows” understandable. It is tied to the model, feature schema, population, and calibration period. Persist all four version IDs. It is neither likelihood nor attack probability, and it will drift if behaviour changes.

### 2. Rule component `R`: auditable contribution table

Recommended initial weights for prototype validation:

| Reason code | Condition (all configurable) | Points |
|---|---|---:|
| `IMPOSSIBLE_TRAVEL` | Reliable consecutive login pair exceeds distance and speed policies | 35 |
| `PRIVILEGE_ESCALATION` | Observed elevation or privileged-group membership change | 30 |
| `FAILED_LOGIN_BURST` | Failed attempts in a time window exceed policy | 20 |
| `BULK_DOWNLOAD` | Bytes/files exceed personal and peer threshold | 20 |
| `SENSITIVE_RESOURCE_ACCESS` | Resource catalog marks object sensitive | 15 |
| `NEW_COUNTRY` | Reliable country not observed in eligible history | 15 |
| `UNKNOWN_DEVICE` | Device not seen with enough user/peer history | 10 |
| `OFF_HOURS_ACTIVITY` | Outside configured schedule and rare in baseline | 8 |
| `NEW_RESOURCE` | Personally novel and peer-rare resource | 8 |

`R = min(100, sum(points))`. Store the condition, observed value, threshold, points, and rule version for every hit. A sensitive resource is a catalog/policy fact; an unusual hour is a baseline comparison. Keep that distinction visible.

### 3. Sequence component `S`

Assign deterministic scores to complete patterns, for example:

- failures → success on new device/location: 70;
- privilege escalation → sensitive access: 80;
- new-country login → privilege escalation → bulk sensitive download: 100.

Use the maximum matched sequence score for `S` in the MVP to avoid multiplying several overlapping versions of the same story. Preserve every match for investigation, but make the arithmetic use explicit.

### 4. Fusion and alert policy

\[
\text{preliminary risk}=0.45A+0.40R+0.15S
\]

Round once at the end. Candidate demonstration severities are `<50 informational`, `50–69 low`, `70–84 medium`, and `85–100 high`; these bands must be chosen from validation workload, not presented as standards. If policy-critical events require a minimum severity, implement an explicit `policy_floor` and show both the pre-floor score and the exact floor rule. Never hide an override.

Example trace:

```text
AI: 92nd benign percentile × 0.45 = 41.40
Rules: UNKNOWN_DEVICE(10) + NEW_COUNTRY(15) + OFF_HOURS(8) = 33
       33 × 0.40 = 13.20
Sequence: fail→success/new-location = 70 × 0.15 = 10.50
Final: round(41.40 + 13.20 + 10.50) = 65
```

### Why not let an LLM or the model choose the whole risk score?

The rule and sequence components express known policy facts; the unsupervised model expresses statistical novelty. Keeping them separate makes failure modes and false positives debuggable. An LLM is unnecessary and would weaken repeatability. If natural-language summaries are added later, they should render only the stored structured evidence and never alter scores or reason codes.

## Explainability strategy

NIST's four XAI principles require an explanation, meaningfulness to the audience, explanation accuracy, and awareness of knowledge limits ([NISTIR 8312](https://doi.org/10.6028/NIST.IR.8312)). SentinelAI can satisfy these without pretending that a tree ensemble proves intent.

### Required alert evidence schema

Every alert should contain:

- `alert_id`, user/entity, event time, status, and severity;
- `final_risk` and the complete `ai`, `rule`, `sequence`, and optional `policy_floor` arithmetic;
- raw model method/score, percentile, threshold, model version, feature-schema version, calibration version, and model status;
- baseline source (`personal`, `personal_peer_blend`, `peer`, or `global`), eligible history count, and confidence;
- stable `reason_code` entries containing human text, observed value, expected value/range, threshold, points, and evidence-event IDs;
- matched sequence steps in time order;
- data-quality warnings, suppression decisions, and missing fields;
- ATT&CK mappings as analyst context, never as proof; and
- acknowledgement/false-positive disposition for evaluation.

### Two layers of explanation

1. **Faithful score explanation:** exact arithmetic and exact rules. This explains why the system emitted and prioritized the alert.
2. **Behavioural context:** top observed baseline deviations such as “02:13 login; personal 99th percentile of time rarity” or “1.8 GB downloaded versus personal p95 110 MB.” These explain what was unusual.

Do not say “Isolation Forest decided this was malicious because of feature X” unless a validated attribution method actually establishes that. Baseline deviations and rule hits are defensible evidence; they are not causal attribution of the ensemble score. A useful phrasing is: “The model ranked this window at the 98th benign percentile; independently, the following measurable deviations and rules were present.”

### Example reason codes

- `LOGIN_TIME_RARE`
- `UNKNOWN_DEVICE`
- `NEW_COUNTRY`
- `IMPOSSIBLE_TRAVEL`
- `FAILED_LOGIN_BURST`
- `FAILURE_THEN_SUCCESS`
- `RESOURCE_PEER_RARE`
- `SENSITIVE_RESOURCE_ACCESS`
- `BULK_DOWNLOAD`
- `PRIVILEGE_ESCALATION`
- `ELEVATION_THEN_SENSITIVE_ACCESS`
- `COLD_START_BASELINE`
- `GEOLOCATION_LOW_CONFIDENCE`
- `MODEL_UNAVAILABLE`

## Reducing false positives

Anomaly-based systems can flag benign deviations and produce false positives, especially when a legitimate activity was absent from the training period ([NIST SP 800-94](https://doi.org/10.6028/NIST.SP.800-94)). The MVP should implement or at least evaluate these controls:

1. **Corroborate signals.** A new device alone is low weight; new device + new country + failed burst + sensitive access is a stronger story.
2. **Model context explicitly.** Role, department, schedule, service-account status, resource sensitivity, and approved maintenance/travel should affect rules and baselines.
3. **Handle VPN/proxy/egress networks.** Microsoft notes VPN masking as an impossible-travel false-positive cause ([official investigation guidance](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-alerts)).
4. **Use geolocation uncertainty.** Subtract accuracy radii and downgrade low-confidence pairs; IP geolocation is not a precise person location ([MaxMind](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy)).
5. **Use personal + peer fallback.** Do not call every first action by a new user anomalous.
6. **Group duplicate evidence.** One incident containing 300 file events is better than 300 alerts. Use user + scenario + rolling time bucket for deduplication.
7. **Tune by alert workload.** Choose thresholds to meet an acceptable false-alerts-per-user-day target on a held-out period, not only the best F1.
8. **Keep per-scenario policies.** Login, download, privilege, and travel signals have different costs; validate thresholds separately.
9. **Protect the baseline.** Update from reviewed-benign/delayed events; retain versions and rollback metadata. Do not let dismissed alerts immediately redefine normal.
10. **Collect analyst disposition.** Record false-positive reason categories (VPN, travel, maintenance, shared device, missing role) and improve the relevant rule/baseline instead of blindly suppressing the user.

## Dataset options

| Dataset | Officially documented contents | Relevance to SentinelAI | Important limitation / use |
|---|---|---|---|
| **CMU SEI CERT Insider Threat Test Dataset** | Synthetic background and malicious-actor data with answer keys and scenario/user identifiers ([official SEI dataset page](https://insights.sei.cmu.edu/library/insider-threat-test-dataset/); [dataset DOI](https://doi.org/10.1184/R1/12841247.v1)). Releases include multiple organizational activity sources. | **Best later benchmark** for insider/employee behaviour and multi-event scenarios. Its synthetic nature aligns with the MVP while providing an independent generator. | Synthetic behaviour is not proof of enterprise performance; releases differ, so record the exact version and scenario mapping. Start with a manageable subset. |
| **LANL Comprehensive / Unified Host and Network datasets** | LANL publishes multi-source enterprise cybersecurity datasets. The Unified Host and Network set includes Windows host events such as event 4624 with user, computer, logon type, authentication package, and time ([official data catalog](https://csr.lanl.gov/data/); [2017 dataset](https://csr.lanl.gov/data/2017/)). | Valuable for authentication/entity-scale experiments, graph/sequence work, and checking whether features run on realistic event volume. | Anonymization and data scale complicate personal semantics; not a direct file-sensitivity/insider label set. Subsample chronologically without breaking sequences. |
| **CICIDS2017** | Labeled benign and attack traffic, PCAPs, and CSV flow features covering protocols and attacks such as brute force, DoS, web attacks, infiltration, botnet, and scanning ([official UNB page](https://www.unb.ca/cic/datasets/ids-2017.html)). | Useful only if SentinelAI adds a **network-flow NIDS** module. | Five days of generated lab traffic; it does not validate unknown-device, employee file-access, or insider-behaviour claims. Do not merge its flow features into the UEBA story without a separately defined entity join. |
| **UNSW-NB15** | Hybrid normal and synthetic attack network traffic, nine attack types, 49 features, labels, and official train/test partitions ([official UNSW page](https://research.unsw.edu.au/projects/unsw-nb15-dataset)). | Another future network-flow benchmark and useful comparison to CICIDS2017. | More than 2.5 million flow records but little direct user/file context. Not the primary dataset for this project. |

### Dataset recommendation

For the current college demo, generate deterministic scenarios with a published schema and seed, and keep clean normal data, calibration data, and labeled attack scenarios separate. Then perform one follow-up evaluation on a small versioned subset of the CERT dataset. This gives fast iteration without claiming the synthetic generator is independent validation.

## Evaluation strategy

### Splits that avoid temporal and identity leakage

Random row splits are inappropriate because adjacent events share user state and feature windows. Scikit-learn warns that ordinary random/k-fold techniques can give unreasonable generalization estimates on time-correlated data and recommends evaluating on future observations ([cross-validation guide](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-of-time-series-data)).

Run two evaluations:

1. **Within-user chronological evaluation**
   - training: earliest known-normal period;
   - calibration/validation: later benign period plus development scenarios for threshold choice;
   - final test: strictly later untouched benign and attack scenarios.

2. **Cold-start/user-disjoint evaluation**
   - entire users belong to only one split;
   - test users use peer/global fallbacks only initially;
   - use `GroupKFold`/`StratifiedGroupKFold` concepts so user groups do not overlap ([scikit-learn `GroupKFold`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html); [`StratifiedGroupKFold`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html)).

No trailing window may include events after its scoring time or cross from test into training. Fit preprocessing, profile statistics, empirical score normalization, thresholds, and weights without final-test data. Scikit-learn defines using information unavailable at prediction time as data leakage and recommends splitting before learned preprocessing ([official common-pitfalls guide](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage)).

### Metrics

Security events are strongly imbalanced. Precision-recall views expose the fraction of correct alerts and recovered attacks more clearly under imbalance than ROC alone ([Saito & Rehmsmeier, 2015](https://doi.org/10.1371/journal.pone.0118432)). Report:

**Primary ranking metrics**

- Average Precision / area under the precision-recall curve;
- precision, recall, and F1 at the chosen operational threshold;
- recall at a fixed alert budget (for example, top 5 alerts/day).

**Operational metrics**

- false positives per 1,000 benign events;
- false alerts per user-day;
- percentage of benign users receiving any alert;
- scenario-level detection rate (at least one useful alert per injected scenario);
- time to first alert from scenario start;
- duplicate alerts per scenario;
- cold-start performance by eligible-history bucket; and
- per-attack-type and per-user/peer-group results.

**Secondary metrics**

- ROC-AUC as a threshold-independent rank statistic;
- confusion matrix and specificity at the selected threshold;
- score/alert stability across several Isolation Forest seeds; keep one fixed seed for the live demo.

Do not use accuracy as the headline metric; predicting every rare attack as normal can produce high accuracy. Include bootstrap confidence intervals over users or scenarios if sample counts allow, while clearly stating the small sample limitation.

### Required evaluation cases

- normal off-hours maintenance (should be suppressed/contextualized);
- new employee with little history;
- traveler using known device with approved travel;
- corporate VPN exit change;
- repeated failures without success;
- repeated failures followed by success on a new device;
- sensitive-file access within job role;
- bulk normal backup/service-account activity;
- insider bulk download after privilege elevation;
- compromised account using new country/device followed by sensitive access;
- missing/invalid coordinates and out-of-order timestamps;
- duplicate events and late ingestion.

Unit-test the risk arithmetic, every rule boundary, Haversine/date-line cases, cold-start blending, sequence order/timeouts, deduplication, and “test data never updates baseline” invariant. End-to-end tests should assert scenario-level alerts and exact reason/contribution traces.

## Recommended MVP architecture

### Architecture choice

Use a **single-process modular monolith** for the local prototype. Streamlit reruns a script when users interact, and offers `st.cache_data` for data/computation results and `st.cache_resource` for global resources such as an ML model ([Streamlit caching/state documentation](https://docs.streamlit.io/develop/api-reference/caching-and-state); [execution model](https://docs.streamlit.io/develop/concepts/architecture)). That is enough for a college demo; a separate API, message broker, microservices, or distributed stream processor would add failure modes without validating the detection idea.

Recommended logical package layout (not implementation in this research step):

```text
app.py                         # Streamlit composition only
sentinel/
  schemas.py                   # typed normalized-event / alert dataclasses or Pydantic models
  ingest/
    normalizer.py              # CSV/synthetic input validation, UTC normalization
  storage/
    database.py                # connection/transaction helper
    repositories.py            # events, profiles, model runs, alerts
  features/
    windows.py                 # prior-only trailing aggregates
    travel.py                  # distance, speed, reliability
    builder.py                 # model-ready feature row
  baselines/
    personal.py
    peer.py
    service.py                 # fallback/blending and confidence
  models/
    base.py                    # fit/score/status interface
    isolation_forest.py
    ocsvm.py                   # optional benchmark
    calibration.py             # empirical percentile mapping
  detection/
    rules.py
    sequences.py
    risk.py
    explanations.py
  services/
    detector.py                # orchestrates one event/scenario
    training.py                # explicit versioned training run
  demo/
    generator.py               # seeded, labeled scenarios
tests/
  test_risk.py
  test_rules.py
  test_travel.py
  test_cold_start.py
  test_sequences.py
  test_scenarios.py
```

### Model interface

The interface should return structured status and scores, not only a number:

```text
fit(training_features, metadata) -> ModelVersion
score(feature_rows) -> {
  status, raw_score, anomaly_percentile,
  model_version, calibration_version, error
}
```

If the model is unavailable or incompatible, persist `MODEL_UNAVAILABLE` and continue rules/sequence scoring with a visibly revised formula/status. Never generate a substitute random score.

### SQLite data model

Minimum tables:

- `events`: immutable normalized events and source payload/checksum;
- `users`, `devices`, `resources`: synthetic entity catalog and context;
- `feature_snapshots`: event/window feature values with feature-schema version;
- `baseline_versions`: eligible time range, counts, peer key, parameters, creation time;
- `model_versions`: estimator parameters, seed, library versions, training range, feature schema, status;
- `calibration_versions`: score distribution and threshold metadata;
- `rule_versions`: rule thresholds and weights;
- `alerts`: total/components/status/model/baseline versions;
- `alert_reasons`: reason code, observed/expected/threshold/contribution/evidence;
- `sequence_matches`: pattern version and ordered event IDs;
- `dispositions`: analyst label and false-positive category.

Use short transactions and parameterized queries. SQLite WAL can allow readers and a writer to proceed concurrently on one host, but there is still only one writer and WAL is not designed for a network filesystem ([SQLite WAL documentation](https://www.sqlite.org/wal.html)). For a single-machine demo, ordinary rollback mode may already suffice; enable WAL only after a small concurrency test and use a SQLite release that includes current WAL fixes.

### Streamlit pages

- **Overview:** counts, risk distribution, recent scenario timeline, model/rule status.
- **Alerts:** sortable live table from SQLite; no disconnected mock alerts.
- **Investigation:** complete evidence, travel calculation, personal/peer comparisons, exact score ledger, sequence timeline.
- **User profile:** known devices/locations, baseline windows, confidence, historical scores.
- **Model & evaluation:** version, training/calibration ranges, metrics, confusion matrix/PR curve, limitations.
- **Scenario runner:** deterministic selector and reset/replay, with visible ground truth only in demo/evaluation mode.

Cache the fitted model with `st.cache_resource`; cache read-only queries/feature transforms briefly with `st.cache_data(ttl=...)`, because Streamlit documentation notes that cached data can otherwise persist across reruns and users ([caching overview](https://docs.streamlit.io/develop/concepts/architecture/caching)). Invalidate caches explicitly after scenario ingestion or retraining.

### Reproducibility and model persistence

Record Python, numpy, scipy, and scikit-learn versions, parameters, random seed, training event range/checksum, feature schema, and evaluation results. Scikit-learn warns that pickle/joblib-style artifacts can execute arbitrary code when loaded and cross-version loading is unsupported ([model-persistence guidance](https://scikit-learn.org/stable/model_persistence.html)). Load only locally produced trusted artifacts; for this small demo, retraining from the versioned synthetic data is an acceptable fallback.

## Limitations

1. **Scope/name mismatch:** the MVP detects behavioural anomalies in identity/file audit events, not malicious packets, exploits, malware, or payload signatures. It must not be marketed as complete network threat detection.
2. **Synthetic-to-real gap:** synthetic regularity can make anomalies unrealistically easy. Performance on the generator is not evidence of enterprise performance.
3. **Unsupervised does not mean malicious:** a rare business event can be an anomaly; a patient attacker can resemble the baseline. Alerts require investigation.
4. **Model score is not probability:** empirical percentiles are ranks relative to one benign calibration set and can shift with drift.
5. **Contaminated/poisoned baselines:** malicious or unusual activity in training can become normal. Delayed reviewed updates reduce but do not remove this risk; NIST documents this weakness of anomaly profiles ([SP 800-94](https://doi.org/10.6028/NIST.SP.800-94)).
6. **IP geolocation limitations:** coordinates approximate an IP/network, not a person; mobile networks, NAT, VPNs, proxies, anycast, and database staleness can invalidate travel reasoning ([MaxMind](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy)).
7. **Cold-start uncertainty:** peer groups can be too small or badly defined; the system must show low confidence rather than overstate personal abnormality.
8. **Explainability boundary:** exact rule/risk arithmetic is explainable; Isolation Forest's raw score is not naturally a causal per-feature explanation. Observed deviations should not be mislabeled as model causality.
9. **Threshold/weight subjectivity:** all proposed windows, rule points, model weights, and severity bands are hypotheses until evaluated with representative costs and workload.
10. **Concept drift:** role, schedule, remote work, and organizational changes alter normal behaviour. Static profiles become stale; aggressively dynamic profiles risk absorbing attacks.
11. **Privacy and governance:** employee monitoring contains sensitive behavioural data. A real deployment needs purpose limitation, access controls, retention policy, audit logging, legal/HR review, and careful UI exposure.
12. **Local architecture ceiling:** Streamlit + SQLite is appropriate for a demo, not high-volume multi-tenant ingestion or concurrent production response.
13. **ATT&CK mapping is contextual:** mapping evidence to T1110/T1078/T1005/T1039 does not establish that an adversary executed the technique.

## Decisions to validate with prototypes before production implementation

1. Whether global Isolation Forest materially beats median/quantile rules, scaled One-Class SVM, and LOF on chronological test scenarios.
2. The feature-window set (5/15/60 minutes and 24 hours) and whether fewer windows achieve the same detection quality.
3. The cold-start blend constant `k`, peer-group definition, and minimum history for “new” device/location claims.
4. The empirical percentile calibration method, alert threshold, and stability across seeds and chronological periods.
5. Risk weights (`0.45/0.40/0.15`), rule points, severity bands, and any explicit policy floors against a target false-alert workload.
6. Impossible-travel minimum distance/speed, accuracy-radius handling, and VPN/corporate-egress suppression.
7. Sequence windows and deduplication rules for compromised-account and insider-download stories.
8. Whether alert explanations let students/analysts correctly identify the evidence and limitations without confusing percentile with probability.
9. SQLite mode/cache invalidation under Streamlit reruns and rapid deterministic scenario replay.
10. Generalization from the in-house generator to a versioned CERT subset, plus a user-disjoint cold-start test.

## Source references

### Anomaly detection and machine learning

- Liu, F. T., Ting, K. M., & Zhou, Z.-H., [“Isolation Forest”](https://doi.org/10.1109/ICDM.2008.17), IEEE ICDM, 2008.
- scikit-learn, [Novelty and Outlier Detection](https://scikit-learn.org/stable/modules/outlier_detection.html).
- scikit-learn, [`IsolationForest` API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).
- Schölkopf et al., [“Estimating the Support of a High-Dimensional Distribution”](https://research.google/pubs/estimating-the-support-of-a-high-dimensional-distribution/), *Neural Computation*, 2001.
- scikit-learn, [`OneClassSVM` API](https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html).
- Breunig et al., [“LOF: Identifying Density-Based Local Outliers”](https://doi.org/10.1145/335191.335388), ACM SIGMOD, 2000.
- scikit-learn, [`LocalOutlierFactor` API](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html) and [novelty-detection example](https://scikit-learn.org/stable/auto_examples/neighbors/plot_lof_novelty_detection.html).
- Hinton & Salakhutdinov, [“Reducing the Dimensionality of Data with Neural Networks”](https://doi.org/10.1126/science.1127647), *Science*, 2006.
- Ruff et al., [“A Unifying Review of Deep and Shallow Anomaly Detection”](https://doi.org/10.1109/JPROC.2021.3052449), *Proceedings of the IEEE*, 2021.
- scikit-learn, [Pipelines and composite estimators](https://scikit-learn.org/stable/modules/compose.html), [common pitfalls/data leakage](https://scikit-learn.org/stable/common_pitfalls.html), and [model persistence](https://scikit-learn.org/stable/model_persistence.html).

### Security behaviour, audit events, and explainability

- NIST, [SP 800-94: Guide to Intrusion Detection and Prevention Systems](https://doi.org/10.6028/NIST.SP.800-94), 2007.
- NIST, [NISTIR 8312: Four Principles of Explainable Artificial Intelligence](https://doi.org/10.6028/NIST.IR.8312), 2021.
- MITRE ATT&CK, [Brute Force T1110](https://attack.mitre.org/techniques/T1110/), [Valid Accounts T1078](https://attack.mitre.org/techniques/T1078/), [Data from Local System T1005](https://attack.mitre.org/techniques/T1005/), and [Data from Network Shared Drive T1039](https://attack.mitre.org/techniques/T1039/).
- Microsoft, [Windows security event reference](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference), [Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon), [event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663), [event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672), and [Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- Microsoft, [Impossible-travel policy documentation](https://learn.microsoft.com/en-us/defender-cloud-apps/policies-threat-protection) and [anomaly-alert investigation guidance](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-alerts).
- MaxMind, [Geolocation accuracy](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy) and [GeoIP developer documentation](https://dev.maxmind.com/geoip/docs/web-services/).
- PostGIS, [`ST_DistanceSphere`](https://postgis.net/docs/ST_DistanceSphere.html) and [`ST_Distance`](https://postgis.net/docs/ST_Distance.html).

### Datasets and evaluation

- Carnegie Mellon University Software Engineering Institute, [CERT Insider Threat Test Dataset](https://insights.sei.cmu.edu/library/insider-threat-test-dataset/) and [dataset DOI](https://doi.org/10.1184/R1/12841247.v1).
- Los Alamos National Laboratory, [Cyber Security Research Data Sets](https://csr.lanl.gov/data/) and [Unified Host and Network Data Set](https://csr.lanl.gov/data/2017/).
- University of New Brunswick Canadian Institute for Cybersecurity, [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).
- UNSW Canberra, [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
- Saito & Rehmsmeier, [“The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets”](https://doi.org/10.1371/journal.pone.0118432), *PLOS ONE*, 2015.
- scikit-learn, [Cross-validation of time series data](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-of-time-series-data), [`GroupKFold`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html), and [`StratifiedGroupKFold`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html).

### Local prototype architecture

- Streamlit, [Execution model and architecture](https://docs.streamlit.io/develop/concepts/architecture), [Caching and state](https://docs.streamlit.io/develop/api-reference/caching-and-state), and [Caching overview](https://docs.streamlit.io/develop/concepts/architecture/caching).
- SQLite, [Write-Ahead Logging](https://www.sqlite.org/wal.html).

