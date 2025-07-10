(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u200))
(define-constant err-not-found (err u201))
(define-constant err-unauthorized (err u202))
(define-constant err-invalid-severity (err u203))
(define-constant err-already-reported (err u204))

(define-constant severity-low u1)
(define-constant severity-medium u2)
(define-constant severity-high u3)
(define-constant severity-critical u4)

(define-constant min-compliance-score u70)

(define-data-var next-event-id uint u1)
(define-data-var next-deviation-id uint u1)

(define-map adverse-events
  { trial-id: uint, event-id: uint }
  {
    participant: principal,
    severity: uint,
    description: (string-ascii 200),
    reported-date: uint,
    reporter: principal,
    resolved: bool,
    resolution-date: (optional uint)
  }
)

(define-map protocol-deviations
  { trial-id: uint, deviation-id: uint }
  {
    participant: (optional principal),
    deviation-type: (string-ascii 100),
    description: (string-ascii 200),
    severity: uint,
    reported-date: uint,
    reporter: principal,
    corrected: bool,
    correction-date: (optional uint)
  }
)

(define-map compliance-scores
  { trial-id: uint }
  {
    total-score: uint,
    last-updated: uint,
    adverse-events-count: uint,
    deviations-count: uint,
    critical-issues: uint,
    compliance-status: bool
  }
)

(define-map regulatory-requirements
  { trial-id: uint, requirement-id: uint }
  {
    requirement-name: (string-ascii 100),
    due-date: uint,
    completed: bool,
    completion-date: (optional uint),
    responsible-party: principal
  }
)

(define-data-var next-requirement-id uint u1)
(define-data-var next-audit-id uint u1)

(define-constant action-type-adverse-event-reported u1)
(define-constant action-type-adverse-event-resolved u2)
(define-constant action-type-deviation-reported u3)
(define-constant action-type-deviation-corrected u4)
(define-constant action-type-requirement-created u5)
(define-constant action-type-requirement-completed u6)
(define-constant action-type-score-updated u7)
(define-constant action-type-compliance-changed u8)

(define-map audit-trail
  { audit-id: uint }
  {
    trial-id: uint,
    action-type: uint,
    actor: principal,
    target-entity-id: (optional uint),
    timestamp: uint,
    block-height: uint,
    previous-state: (optional (string-ascii 500)),
    new-state: (optional (string-ascii 500)),
    reason: (optional (string-ascii 200)),
    severity: (optional uint),
    validated: bool,
    validator: (optional principal),
    validation-timestamp: (optional uint)
  }
)

(define-map trial-audit-summaries
  { trial-id: uint }
  {
    total-actions: uint,
    last-action-date: uint,
    last-compliance-change: uint,
    critical-actions-count: uint,
    validation-rate: uint,
    audit-score: uint
  }
)

(define-map audit-queries
  { query-id: uint }
  {
    trial-id: uint,
    requester: principal,
    query-type: uint,
    date-range-start: uint,
    date-range-end: uint,
    action-types: (list 10 uint),
    created-timestamp: uint,
    results-count: uint,
    query-status: bool
  }
)

(define-data-var next-query-id uint u1)

(define-public (report-adverse-event (trial-id uint) (participant principal) (severity uint) (description (string-ascii 200)))
  (let ((event-id (var-get next-event-id)))
    (asserts! (and (>= severity severity-low) (<= severity severity-critical)) err-invalid-severity)
    
    (map-insert adverse-events
      { trial-id: trial-id, event-id: event-id }
      {
        participant: participant,
        severity: severity,
        description: description,
        reported-date: stacks-block-height,
        reporter: tx-sender,
        resolved: false,
        resolution-date: none
      }
    )
    
    (var-set next-event-id (+ event-id u1))
    (unwrap! (create-audit-entry trial-id action-type-adverse-event-reported tx-sender (some event-id) none (some description) (some severity)) (err u210))
    (unwrap! (update-compliance-score trial-id)  (err u205))
    (ok event-id)
  )
)

(define-public (resolve-adverse-event (trial-id uint) (event-id uint))
  (let ((event (unwrap! (map-get? adverse-events { trial-id: trial-id, event-id: event-id }) err-not-found)))
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (get reporter event))) err-unauthorized)
    
    (map-set adverse-events
      { trial-id: trial-id, event-id: event-id }
      (merge event { resolved: true, resolution-date: (some stacks-block-height) })
    )
    
    (unwrap! (create-audit-entry trial-id action-type-adverse-event-resolved tx-sender (some event-id) (some "unresolved") (some "resolved") none) (err u211))
    (unwrap! (update-compliance-score trial-id) (err u206))
    (ok true)
  )
)

(define-public (report-protocol-deviation (trial-id uint) (participant (optional principal)) (deviation-type (string-ascii 100)) (description (string-ascii 200)) (severity uint))
  (let ((deviation-id (var-get next-deviation-id)))
    (asserts! (and (>= severity severity-low) (<= severity severity-critical)) err-invalid-severity)
    
    (map-insert protocol-deviations
      { trial-id: trial-id, deviation-id: deviation-id }
      {
        participant: participant,
        deviation-type: deviation-type,
        description: description,
        severity: severity,
        reported-date: stacks-block-height,
        reporter: tx-sender,
        corrected: false,
        correction-date: none
      }
    )
    
    (var-set next-deviation-id (+ deviation-id u1))
    (unwrap! (create-audit-entry trial-id action-type-deviation-reported tx-sender (some deviation-id) none (some description) (some severity)) (err u212))
    (unwrap! (update-compliance-score trial-id) (err u207))
    (ok deviation-id)
  )
)

(define-public (correct-protocol-deviation (trial-id uint) (deviation-id uint))
  (let ((deviation (unwrap! (map-get? protocol-deviations { trial-id: trial-id, deviation-id: deviation-id }) err-not-found)))
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (get reporter deviation))) err-unauthorized)
    
    (map-set protocol-deviations
      { trial-id: trial-id, deviation-id: deviation-id }
      (merge deviation { corrected: true, correction-date: (some stacks-block-height) })
    )
    
    (unwrap! (create-audit-entry trial-id action-type-deviation-corrected tx-sender (some deviation-id) (some "uncorrected") (some "corrected") none) (err u213))
    (unwrap! (update-compliance-score trial-id) (err u208))
    (ok true)
  )
)

(define-public (add-regulatory-requirement (trial-id uint) (requirement-name (string-ascii 100)) (due-date uint) (responsible-party principal))
  (let ((requirement-id (var-get next-requirement-id)))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    
    (map-insert regulatory-requirements
      { trial-id: trial-id, requirement-id: requirement-id }
      {
        requirement-name: requirement-name,
        due-date: due-date,
        completed: false,
        completion-date: none,
        responsible-party: responsible-party
      }
    )
    
    (var-set next-requirement-id (+ requirement-id u1))
    (unwrap! (create-audit-entry trial-id action-type-requirement-created tx-sender (some requirement-id) none (some requirement-name) none) (err u214))
    (ok requirement-id)
  )
)

(define-public (complete-regulatory-requirement (trial-id uint) (requirement-id uint))
  (let ((requirement (unwrap! (map-get? regulatory-requirements { trial-id: trial-id, requirement-id: requirement-id }) err-not-found)))
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (get responsible-party requirement))) err-unauthorized)
    
    (map-set regulatory-requirements
      { trial-id: trial-id, requirement-id: requirement-id }
      (merge requirement { completed: true, completion-date: (some stacks-block-height) })
    )
    
    (unwrap! (create-audit-entry trial-id action-type-requirement-completed tx-sender (some requirement-id) (some "incomplete") (some "completed") none) (err u215))
    (unwrap! (update-compliance-score trial-id) (err u209))
    (ok true)
  )
)

(define-private (calculate-compliance-score (trial-id uint))
  (let (
    (base-score u100)
    (adverse-events-penalty (get-adverse-events-penalty trial-id))
    (deviations-penalty (get-deviations-penalty trial-id))
    (requirements-penalty (get-requirements-penalty trial-id))
  )
    (let ((total-penalty (+ adverse-events-penalty (+ deviations-penalty requirements-penalty))))
      (if (> total-penalty base-score)
        u0
        (- base-score total-penalty)
      )
    )
  )
)

(define-private (get-adverse-events-penalty (trial-id uint))
  (let (
    (critical-events (count-events-by-severity trial-id severity-critical))
    (high-events (count-events-by-severity trial-id severity-high))
    (medium-events (count-events-by-severity trial-id severity-medium))
    (low-events (count-events-by-severity trial-id severity-low))
  )
    (+ (* critical-events u20) (+ (* high-events u10) (+ (* medium-events u5) (* low-events u2))))
  )
)

(define-private (get-deviations-penalty (trial-id uint))
  (let (
    (critical-deviations (count-deviations-by-severity trial-id severity-critical))
    (high-deviations (count-deviations-by-severity trial-id severity-high))
    (medium-deviations (count-deviations-by-severity trial-id severity-medium))
    (low-deviations (count-deviations-by-severity trial-id severity-low))
  )
    (+ (* critical-deviations u15) (+ (* high-deviations u8) (+ (* medium-deviations u4) (* low-deviations u1))))
  )
)

(define-private (get-requirements-penalty (trial-id uint))
  (let ((overdue-requirements (count-overdue-requirements trial-id)))
    (* overdue-requirements u10)
  )
)

(define-private (count-events-by-severity (trial-id uint) (target-severity uint))
  u0
)

(define-private (count-deviations-by-severity (trial-id uint) (target-severity uint))
  u0
)

(define-private (count-overdue-requirements (trial-id uint))
  u0
)

(define-private (count-critical-issues (trial-id uint))
  (+ (count-events-by-severity trial-id severity-critical) (count-deviations-by-severity trial-id severity-critical))
)

(define-public (update-compliance-score (trial-id uint))
  (let (
    (new-score (calculate-compliance-score trial-id))
    (critical-count (count-critical-issues trial-id))
    (compliance-status (>= new-score min-compliance-score))
  )
    (map-set compliance-scores
      { trial-id: trial-id }
      {
        total-score: new-score,
        last-updated: stacks-block-height,
        adverse-events-count: u0,
        deviations-count: u0,
        critical-issues: critical-count,
        compliance-status: compliance-status
      }
    )
    (unwrap! (create-audit-entry trial-id action-type-score-updated tx-sender none none none none) (err u216))
    (ok new-score)
  )
)

(define-public (check-compliance-status (trial-id uint))
  (let ((compliance (get-compliance-score trial-id)))
    (match compliance
      score-data (ok (get compliance-status score-data))
      (ok true)
    )
  )
)

(define-read-only (get-adverse-event (trial-id uint) (event-id uint))
  (map-get? adverse-events { trial-id: trial-id, event-id: event-id })
)

(define-read-only (get-protocol-deviation (trial-id uint) (deviation-id uint))
  (map-get? protocol-deviations { trial-id: trial-id, deviation-id: deviation-id })
)

(define-read-only (get-compliance-score (trial-id uint))
  (map-get? compliance-scores { trial-id: trial-id })
)

(define-read-only (get-regulatory-requirement (trial-id uint) (requirement-id uint))
  (map-get? regulatory-requirements { trial-id: trial-id, requirement-id: requirement-id })
)

(define-read-only (is-trial-compliant (trial-id uint))
  (match (map-get? compliance-scores { trial-id: trial-id })
    compliance-data (>= (get total-score compliance-data) min-compliance-score)
    true
  )
)

(define-private (create-audit-entry (trial-id uint) (action-type uint) (actor principal) (target-entity-id (optional uint)) (previous-state (optional (string-ascii 500))) (new-state (optional (string-ascii 500))) (severity (optional uint)))
  (let ((audit-id (var-get next-audit-id)))
    (map-insert audit-trail
      { audit-id: audit-id }
      {
        trial-id: trial-id,
        action-type: action-type,
        actor: actor,
        target-entity-id: target-entity-id,
        timestamp: stacks-block-height,
        block-height: stacks-block-height,
        previous-state: previous-state,
        new-state: new-state,
        reason: none,
        severity: severity,
        validated: false,
        validator: none,
        validation-timestamp: none
      }
    )
    (var-set next-audit-id (+ audit-id u1))
    (unwrap! (update-trial-audit-summary trial-id action-type) (err u217))
    (ok audit-id)
  )
)

(define-private (update-trial-audit-summary (trial-id uint) (action-type uint))
  (let (
    (current-summary (default-to 
      { total-actions: u0, last-action-date: u0, last-compliance-change: u0, critical-actions-count: u0, validation-rate: u0, audit-score: u100 }
      (map-get? trial-audit-summaries { trial-id: trial-id })
    ))
    (is-critical-action (or (is-eq action-type action-type-adverse-event-reported) (is-eq action-type action-type-deviation-reported)))
    (is-compliance-action (or (is-eq action-type action-type-score-updated) (is-eq action-type action-type-compliance-changed)))
  )
    (map-set trial-audit-summaries
      { trial-id: trial-id }
      {
        total-actions: (+ (get total-actions current-summary) u1),
        last-action-date: stacks-block-height,
        last-compliance-change: (if is-compliance-action stacks-block-height (get last-compliance-change current-summary)),
        critical-actions-count: (+ (get critical-actions-count current-summary) (if is-critical-action u1 u0)),
        validation-rate: (get validation-rate current-summary),
        audit-score: (calculate-audit-score trial-id)
      }
    )
    (ok true)
  )
)

(define-private (calculate-audit-score (trial-id uint))
  (let (
    (summary (default-to 
      { total-actions: u0, last-action-date: u0, last-compliance-change: u0, critical-actions-count: u0, validation-rate: u0, audit-score: u100 }
      (map-get? trial-audit-summaries { trial-id: trial-id })
    ))
    (base-score u100)
    (critical-penalty (* (get critical-actions-count summary) u5))
    (activity-bonus (if (> (get total-actions summary) u10) u10 u0))
  )
    (let ((score-after-penalty (if (> critical-penalty base-score) u0 (- base-score critical-penalty))))
      (+ score-after-penalty activity-bonus)
    )
  )
)

(define-public (validate-audit-entry (audit-id uint) (validation-note (optional (string-ascii 200))))
  (let ((audit-entry (unwrap! (map-get? audit-trail { audit-id: audit-id }) err-not-found)))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (not (get validated audit-entry)) (err u218))
    
    (map-set audit-trail
      { audit-id: audit-id }
      (merge audit-entry {
        validated: true,
        validator: (some tx-sender),
        validation-timestamp: (some stacks-block-height),
        reason: validation-note
      })
    )
    (ok true)
  )
)

(define-public (create-audit-query (trial-id uint) (query-type uint) (date-range-start uint) (date-range-end uint) (action-types (list 10 uint)))
  (let ((query-id (var-get next-query-id)))
    (map-insert audit-queries
      { query-id: query-id }
      {
        trial-id: trial-id,
        requester: tx-sender,
        query-type: query-type,
        date-range-start: date-range-start,
        date-range-end: date-range-end,
        action-types: action-types,
        created-timestamp: stacks-block-height,
        results-count: u0,
        query-status: true
      }
    )
    (var-set next-query-id (+ query-id u1))
    (ok query-id)
  )
)

(define-public (export-audit-trail (trial-id uint) (start-date uint) (end-date uint))
  (begin
    (asserts! (or (is-eq tx-sender contract-owner) (is-authorized-auditor tx-sender trial-id)) err-unauthorized)
    (let ((query-id (unwrap! (create-audit-query trial-id u1 start-date end-date (list action-type-adverse-event-reported action-type-adverse-event-resolved action-type-deviation-reported action-type-deviation-corrected action-type-requirement-created action-type-requirement-completed action-type-score-updated action-type-compliance-changed)) (err u219))))
      (ok query-id)
    )
  )
)

(define-private (is-authorized-auditor (auditor principal) (trial-id uint))
  true
)

(define-read-only (get-audit-entry (audit-id uint))
  (map-get? audit-trail { audit-id: audit-id })
)

(define-read-only (get-trial-audit-summary (trial-id uint))
  (map-get? trial-audit-summaries { trial-id: trial-id })
)

(define-read-only (get-audit-query (query-id uint))
  (map-get? audit-queries { query-id: query-id })
)

(define-read-only (get-latest-audit-entries (trial-id uint) (limit uint))
  (begin
    (asserts! (<= limit u50) (err u220))
    (ok (var-get next-audit-id))
  )
)

(define-read-only (verify-audit-integrity (trial-id uint))
  (let (
    (summary (get-trial-audit-summary trial-id))
    (current-audit-id (var-get next-audit-id))
  )
    (match summary
      summary-data (ok {
        integrity-score: (get audit-score summary-data),
        total-entries: (get total-actions summary-data),
        validation-rate: (get validation-rate summary-data),
        last-activity: (get last-action-date summary-data)
      })
      (ok { integrity-score: u100, total-entries: u0, validation-rate: u0, last-activity: u0 })
    )
  )
)