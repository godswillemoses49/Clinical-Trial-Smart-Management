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