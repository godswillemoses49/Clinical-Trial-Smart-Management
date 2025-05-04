(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-state (err u104))
(define-constant err-insufficient-funds (err u105))
(define-constant err-consent-required (err u106))

;; Trial status enum: 0=Planned, 1=Recruiting, 2=Active, 3=Completed, 4=Terminated
(define-data-var next-trial-id uint u1)

(define-map trials
  { trial-id: uint }
  {
    name: (string-ascii 100),
    description: (string-ascii 500),
    principal-investigator: principal,
    status: uint,
    total-funding: uint,
    released-funding: uint,
    start-date: uint,
    end-date: uint
  }
)

(define-map participants
  { trial-id: uint, participant: principal }
  {
    consent-given: bool,
    enrollment-date: uint,
    data-validated: bool,
    withdrawn: bool
  }
)

(define-map trial-data
  { trial-id: uint, participant: principal, data-point-id: uint }
  {
    timestamp: uint,
    data-hash: (buff 32),
    validated: bool,
    validator: (optional principal)
  }
)

(define-map trial-milestones
  { trial-id: uint, milestone-id: uint }
  {
    description: (string-ascii 100),
    funding-amount: uint,
    completed: bool,
    completion-date: (optional uint)
  }
)

(define-data-var next-data-point-id uint u1)
(define-data-var next-milestone-id uint u1)

(define-public (create-trial (name (string-ascii 100)) (description (string-ascii 500)) (total-funding uint) (start-date uint) (end-date uint))
  (let ((trial-id (var-get next-trial-id)))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-insert trials
      { trial-id: trial-id }
      {
        name: name,
        description: description,
        principal-investigator: tx-sender,
        status: u0,
        total-funding: total-funding,
        released-funding: u0,
        start-date: start-date,
        end-date: end-date
      }
    )
    (var-set next-trial-id (+ trial-id u1))
    (ok trial-id)
  )
)

(define-public (update-trial-status (trial-id uint) (new-status uint))
  (let ((trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found)))
    (asserts! (is-eq tx-sender (get principal-investigator trial)) err-unauthorized)
    (asserts! (<= new-status u4) err-invalid-state)
    (map-set trials
      { trial-id: trial-id }
      (merge trial { status: new-status })
    )
    (ok true)
  )
)

(define-public (enroll-participant (trial-id uint) (participant principal))
  (let ((trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found)))
    (asserts! (is-eq tx-sender (get principal-investigator trial)) err-unauthorized)
    (asserts! (is-eq (get status trial) u1) err-invalid-state)
    (asserts! (is-none (map-get? participants { trial-id: trial-id, participant: participant })) err-already-exists)
    (map-insert participants
      { trial-id: trial-id, participant: participant }
      {
        consent-given: false,
        enrollment-date: stacks-block-height,
        data-validated: false,
        withdrawn: false
      }
    )
    (ok true)
  )
)

(define-public (give-consent (trial-id uint))
  (let ((participant-data (unwrap! (map-get? participants { trial-id: trial-id, participant: tx-sender }) err-not-found)))
    (map-set participants
      { trial-id: trial-id, participant: tx-sender }
      (merge participant-data { consent-given: true })
    )
    (ok true)
  )
)

(define-public (withdraw-consent (trial-id uint))
  (let ((participant-data (unwrap! (map-get? participants { trial-id: trial-id, participant: tx-sender }) err-not-found)))
    (map-set participants
      { trial-id: trial-id, participant: tx-sender }
      (merge participant-data { withdrawn: true })
    )
    (ok true)
  )
)

(define-public (add-data-point (trial-id uint) (participant principal) (data-hash (buff 32)))
  (let (
    (trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found))
    (participant-data (unwrap! (map-get? participants { trial-id: trial-id, participant: participant }) err-not-found))
    (data-point-id (var-get next-data-point-id))
  )
    (asserts! (is-eq tx-sender (get principal-investigator trial)) err-unauthorized)
    (asserts! (get consent-given participant-data) err-consent-required)
    (asserts! (not (get withdrawn participant-data)) err-invalid-state)
    
    (map-insert trial-data
      { trial-id: trial-id, participant: participant, data-point-id: data-point-id }
      {
        timestamp: stacks-block-height,
        data-hash: data-hash,
        validated: false,
        validator: none
      }
    )
    (var-set next-data-point-id (+ data-point-id u1))
    (ok data-point-id)
  )
)

(define-public (validate-data-point (trial-id uint) (participant principal) (data-point-id uint))
  (let (
    (trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found))
    (data-point (unwrap! (map-get? trial-data { trial-id: trial-id, participant: participant, data-point-id: data-point-id }) err-not-found))
  )
    (asserts! (is-eq tx-sender (get principal-investigator trial)) err-unauthorized)
    
    (map-set trial-data
      { trial-id: trial-id, participant: participant, data-point-id: data-point-id }
      (merge data-point { validated: true, validator: (some tx-sender) })
    )
    (ok true)
  )
)

(define-public (add-milestone (trial-id uint) (description (string-ascii 100)) (funding-amount uint))
  (let (
    (trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found))
    (milestone-id (var-get next-milestone-id))
  )
    (asserts! (is-eq tx-sender (get principal-investigator trial)) err-unauthorized)
    
    (map-insert trial-milestones
      { trial-id: trial-id, milestone-id: milestone-id }
      {
        description: description,
        funding-amount: funding-amount,
        completed: false,
        completion-date: none
      }
    )
    (var-set next-milestone-id (+ milestone-id u1))
    (ok milestone-id)
  )
)

(define-public (complete-milestone (trial-id uint) (milestone-id uint))
  (let (
    (trial (unwrap! (map-get? trials { trial-id: trial-id }) err-not-found))
    (milestone (unwrap! (map-get? trial-milestones { trial-id: trial-id, milestone-id: milestone-id }) err-not-found))
  )
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (not (get completed milestone)) err-invalid-state)
    
    (map-set trial-milestones
      { trial-id: trial-id, milestone-id: milestone-id }
      (merge milestone { completed: true, completion-date: (some stacks-block-height) })
    )
    
    (map-set trials
      { trial-id: trial-id }
      (merge trial { released-funding: (+ (get released-funding trial) (get funding-amount milestone)) })
    )
    (ok true)
  )
)

(define-read-only (get-trial (trial-id uint))
  (map-get? trials { trial-id: trial-id })
)

(define-read-only (get-participant (trial-id uint) (participant principal))
  (map-get? participants { trial-id: trial-id, participant: participant })
)

(define-read-only (get-data-point (trial-id uint) (participant principal) (data-point-id uint))
  (map-get? trial-data { trial-id: trial-id, participant: participant, data-point-id: data-point-id })
)

(define-read-only (get-milestone (trial-id uint) (milestone-id uint))
  (map-get? trial-milestones { trial-id: trial-id, milestone-id: milestone-id })
)
