# Personal and peer behavioral baselines

SentinelAI now produces two separate kinds of behavioral evidence for an event. This capability does not change the Isolation Forest feature schema, deterministic rules, risk weights, or final risk score.

## Peer definition

A peer group is the exact pair `department + normal_privilege` from existing employee metadata. Assignment is deterministic; it does not use clustering, learned embeddings, activity data, or the event's current privilege. When an employee is assessed, that employee is excluded from the peer population so their own history cannot define peer normality.

## Eligible history and self-exclusion

Both baselines use only events that:

- occurred strictly before the evaluated event;
- have a different event ID;
- have `scenario == "normal"`; and
- are not marked suspicious.

The personal profile uses the target employee's eligible history. The peer profile uses eligible history from other employees with the same peer key. This makes the result reproducible and prevents the current event from influencing its own assessment.

## Baseline statistics

The profiles retain the existing normal-history concepts:

- 5th-to-95th percentile successful-login hour range;
- frequent countries and cities;
- known-device observations;
- average failed-login count;
- average non-zero download count and per-event download size;
- frequent file sensitivities; and
- modal privilege.

Device identifiers are employee-specific in the synthetic data. The peer profile records them for traceability, but peer assessment compares whether the device is registered to the evaluated employee rather than treating another employee's device ID as normal.

Only signals supported by relevant history are emitted. For example, a peer population with no download history does not invent a download expectation.

## Deviation semantics

`personal_deviation` answers: “How unusual is this event for this employee?”

`peer_deviation` answers: “How unusual is this event compared with other employees in the same department and normal role?”

Each value is the fraction of applicable, history-supported signals marked unusual. Signal records retain the observed value, expected value, and unusual/normal decision. A value of `None` means there was no usable history for that comparison. These deviations are behavioral evidence, not attack probabilities and not final risk scores.

The assessment also labels the comparison case: normal/normal, abnormal/normal, normal/abnormal, abnormal/abnormal, insufficient personal history, insufficient peer history, or insufficient history on both sides.

## Confidence and sparse groups

Personal confidence keeps the established history-volume rule: it rises linearly to 1.0 at 30 normal events.

Peer confidence is independent. It is the product of:

1. normal-event volume, capped at 60 events;
2. distinct contributing peers, capped at three peers; and
3. coverage of login, download, file, known-device, and privilege history.

Peer status is:

- `no_history` when no other peer contributes usable normal history;
- `sparse` when fewer than two peers contribute or confidence is below 0.5; or
- `sufficient` otherwise.

A single comparable employee can produce inspectable evidence, but its member-confidence component is capped at one third and the profile remains explicitly sparse. A single-member group therefore has no peer baseline after the target employee is excluded.

## Persistence and observability

Peer profiles and assessments are derived from employees and activity history and are not persisted in new tables. Existing SQLite databases initialize without migration. A live `DetectionResult` carries its assessment, and `SentinelService.behavioural_assessment(event_id)` deterministically reconstructs structured evidence for a persisted event.

## Current limitations

- Peer identity assumes department and configured normal privilege are accurate and sufficiently stable.
- The initial demo has strong employee-role groups but deliberately sparse manager groups.
- Categorical frequency and simple averages do not model multimodal work patterns or concept drift.
- Confidence measures data support, not correctness.
- The deviation fraction gives all applicable signals equal weight. It is deliberately not fused into risk yet.
- No global fallback is implemented in this milestone.
