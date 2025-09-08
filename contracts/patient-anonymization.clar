;; Patient Anonymization and Privacy Layer
;; Provides secure patient identity management with anonymization features

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u400))
(define-constant ERR-IDENTITY-NOT-FOUND (err u401))
(define-constant ERR-IDENTITY-ALREADY-EXISTS (err u402))
(define-constant ERR-INVALID-HASH (err u403))
(define-constant ERR-CONSENT-NOT-GIVEN (err u404))
(define-constant ERR-REVOKED-ACCESS (err u405))
(define-constant ERR-ENCRYPTION-FAILED (err u406))
(define-constant ERR-DECRYPTION-FAILED (err u407))
(define-constant ERR-INVALID-AUTHORIZATION (err u408))

;; Constants
(define-constant CONTRACT-ADMIN tx-sender)
(define-constant ANONYMIZATION-ENABLED true)
(define-constant DEFAULT-RETENTION-PERIOD u52560) ;; ~1 year in blocks

;; Data variables
(define-data-var next-identity-id uint u1)
(define-data-var privacy-enabled bool true)
(define-data-var encryption-key-hash (buff 32) 0x0000000000000000000000000000000000000000000000000000000000000000)

;; Anonymous identity mapping system
(define-map patient-identities
  { identity-id: uint }
  {
    real-identity-hash: (buff 32),
    anonymous-id: (buff 32),
    trial-id: uint,
    consent-timestamp: uint,
    consent-expiry: uint,
    data-access-level: uint, ;; 1=minimal, 2=standard, 3=full
    anonymization-level: uint, ;; 1=pseudonym, 2=anonymous, 3=fully-encrypted
    created-block: uint,
    last-accessed: uint,
    access-count: uint
  }
)

;; Data access permissions
(define-map access-permissions
  { identity-id: uint, accessor: principal }
  {
    permission-level: uint,
    granted-timestamp: uint,
    expiry-timestamp: uint,
    purpose: (string-ascii 100),
    access-granted: bool,
    revoked: bool
  }
)

;; Anonymized data storage
(define-map anonymized-data
  { identity-id: uint, data-category: (string-ascii 50) }
  {
    encrypted-data-hash: (buff 32),
    anonymization-method: (string-ascii 30),
    data-integrity-hash: (buff 32),
    access-log: (list 5 principal),
    last-modified: uint,
    retention-expiry: uint
  }
)

;; Privacy audit trail
(define-map privacy-audit-log
  { audit-id: uint }
  {
    identity-id: uint,
    action-type: (string-ascii 50),
    actor: principal,
    timestamp: uint,
    data-accessed: (string-ascii 100),
    justification: (string-ascii 100),
    approval-required: bool,
    approved: bool
  }
)

;; Data retention policies
(define-map retention-policies
  { trial-id: uint, data-type: (string-ascii 50) }
  {
    retention-period: uint,
    deletion-method: (string-ascii 30),
    archive-required: bool,
    compliance-standard: (string-ascii 50),
    auto-deletion: bool
  }
)

(define-data-var next-audit-id uint u1)

;; Register new patient with anonymization
(define-public (register-anonymous-patient
  (trial-id uint)
  (real-identity-hash (buff 32))
  (consent-duration uint)
  (access-level uint)
  (anonymization-level uint))
  (let
    ((identity-id (var-get next-identity-id))
     (anonymous-id (generate-anonymous-id real-identity-hash identity-id))
     (consent-expiry (+ stacks-block-height consent-duration)))
    
    (asserts! (var-get privacy-enabled) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= access-level u1) (<= access-level u3)) (err u409))
    (asserts! (and (>= anonymization-level u1) (<= anonymization-level u3)) (err u410))
    
    (map-set patient-identities { identity-id: identity-id } {
      real-identity-hash: real-identity-hash,
      anonymous-id: anonymous-id,
      trial-id: trial-id,
      consent-timestamp: stacks-block-height,
      consent-expiry: consent-expiry,
      data-access-level: access-level,
      anonymization-level: anonymization-level,
      created-block: stacks-block-height,
      last-accessed: stacks-block-height,
      access-count: u0
    })
    
    (var-set next-identity-id (+ identity-id u1))
    (unwrap-panic (log-privacy-action identity-id "PATIENT_REGISTERED" tx-sender "New anonymous patient created"))
    (ok identity-id)))

;; Grant data access permission to authorized party
(define-public (grant-access-permission
  (identity-id uint)
  (accessor principal)
  (permission-level uint)
  (access-duration uint)
  (purpose (string-ascii 100)))
  (let
    ((identity (unwrap! (map-get? patient-identities { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
     (expiry (+ stacks-block-height access-duration)))
    
    (asserts! (is-authorized-for-identity identity-id tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (<= stacks-block-height (get consent-expiry identity)) ERR-CONSENT-NOT-GIVEN)
    (asserts! (and (>= permission-level u1) (<= permission-level u3)) (err u411))
    
    (map-set access-permissions { identity-id: identity-id, accessor: accessor } {
      permission-level: permission-level,
      granted-timestamp: stacks-block-height,
      expiry-timestamp: expiry,
      purpose: purpose,
      access-granted: true,
      revoked: false
    })
    
    (unwrap-panic (log-privacy-action identity-id "ACCESS_GRANTED" accessor purpose))
    (ok true)))

;; Store anonymized patient data
(define-public (store-anonymized-data
  (identity-id uint)
  (data-category (string-ascii 50))
  (encrypted-data-hash (buff 32))
  (anonymization-method (string-ascii 30)))
  (let
    ((identity (unwrap! (map-get? patient-identities { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
     (integrity-hash (hash160 encrypted-data-hash))
     (retention-expiry (+ stacks-block-height DEFAULT-RETENTION-PERIOD)))
    
    (asserts! (has-data-access-permission identity-id tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (<= stacks-block-height (get consent-expiry identity)) ERR-CONSENT-NOT-GIVEN)
    
    (map-set anonymized-data { identity-id: identity-id, data-category: data-category } {
      encrypted-data-hash: encrypted-data-hash,
      anonymization-method: anonymization-method,
      data-integrity-hash: integrity-hash,
      access-log: (list tx-sender),
      last-modified: stacks-block-height,
      retention-expiry: retention-expiry
    })
    
    ;; Update access tracking
    (map-set patient-identities { identity-id: identity-id }
      (merge identity {
        last-accessed: stacks-block-height,
        access-count: (+ (get access-count identity) u1)
      }))
    
    (unwrap-panic (log-privacy-action identity-id "DATA_STORED" tx-sender data-category))
    (ok true)))

;; Retrieve anonymized data with access control
(define-public (access-anonymized-data
  (identity-id uint)
  (data-category (string-ascii 50))
  (access-justification (string-ascii 100)))
  (let
    ((identity (unwrap! (map-get? patient-identities { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
     (data-record (unwrap! (map-get? anonymized-data { identity-id: identity-id, data-category: data-category }) ERR-IDENTITY-NOT-FOUND))
     (permission (unwrap! (map-get? access-permissions { identity-id: identity-id, accessor: tx-sender }) ERR-NOT-AUTHORIZED)))
    
    (asserts! (get access-granted permission) ERR-NOT-AUTHORIZED)
    (asserts! (not (get revoked permission)) ERR-REVOKED-ACCESS)
    (asserts! (<= stacks-block-height (get expiry-timestamp permission)) ERR-NOT-AUTHORIZED)
    (asserts! (<= stacks-block-height (get consent-expiry identity)) ERR-CONSENT-NOT-GIVEN)
    
    ;; Log data access
    (unwrap-panic (log-privacy-action identity-id "DATA_ACCESSED" tx-sender access-justification))
    
    ;; Update access tracking
    (map-set patient-identities { identity-id: identity-id }
      (merge identity {
        last-accessed: stacks-block-height,
        access-count: (+ (get access-count identity) u1)
      }))
    
    (ok {
      encrypted-data-hash: (get encrypted-data-hash data-record),
      anonymization-method: (get anonymization-method data-record),
      access-level: (get data-access-level identity),
      anonymization-level: (get anonymization-level identity)
    })))

;; Revoke data access permission
(define-public (revoke-access-permission
  (identity-id uint)
  (accessor principal)
  (revocation-reason (string-ascii 100)))
  (let
    ((permission (unwrap! (map-get? access-permissions { identity-id: identity-id, accessor: accessor }) ERR-NOT-AUTHORIZED)))
    
    (asserts! (is-authorized-for-identity identity-id tx-sender) ERR-NOT-AUTHORIZED)
    
    (map-set access-permissions { identity-id: identity-id, accessor: accessor }
      (merge permission { 
        revoked: true,
        access-granted: false 
      }))
    
    (unwrap-panic (log-privacy-action identity-id "ACCESS_REVOKED" accessor revocation-reason))
    (ok true)))

;; Private helper functions
(define-private (generate-anonymous-id (real-hash (buff 32)) (identity-id uint))
  (hash160 (concat real-hash (unwrap-panic (to-consensus-buff? identity-id)))))

(define-private (is-authorized-for-identity (identity-id uint) (actor principal))
  (or (is-eq actor CONTRACT-ADMIN)
      (has-data-access-permission identity-id actor)))

(define-private (has-data-access-permission (identity-id uint) (accessor principal))
  (match (map-get? access-permissions { identity-id: identity-id, accessor: accessor })
    permission (and (get access-granted permission) 
                    (not (get revoked permission))
                    (<= stacks-block-height (get expiry-timestamp permission)))
    false))

(define-private (log-privacy-action 
  (identity-id uint) 
  (action-type (string-ascii 50)) 
  (actor principal) 
  (details (string-ascii 100)))
  (let ((audit-id (var-get next-audit-id)))
    (map-set privacy-audit-log { audit-id: audit-id } {
      identity-id: identity-id,
      action-type: action-type,
      actor: actor,
      timestamp: stacks-block-height,
      data-accessed: details,
      justification: details,
      approval-required: false,
      approved: true
    })
    (var-set next-audit-id (+ audit-id u1))
    (ok true)))

;; Read-only functions
(define-read-only (get-identity-info (identity-id uint))
  (map-get? patient-identities { identity-id: identity-id }))

(define-read-only (get-access-permission (identity-id uint) (accessor principal))
  (map-get? access-permissions { identity-id: identity-id, accessor: accessor }))

(define-read-only (get-anonymized-data-info (identity-id uint) (data-category (string-ascii 50)))
  (map-get? anonymized-data { identity-id: identity-id, data-category: data-category }))

(define-read-only (get-privacy-audit-entry (audit-id uint))
  (map-get? privacy-audit-log { audit-id: audit-id }))

(define-read-only (check-consent-status (identity-id uint))
  (match (map-get? patient-identities { identity-id: identity-id })
    identity (ok {
      consent-valid: (<= stacks-block-height (get consent-expiry identity)),
      consent-expiry: (get consent-expiry identity),
      access-level: (get data-access-level identity),
      anonymization-level: (get anonymization-level identity)
    })
    ERR-IDENTITY-NOT-FOUND))

(define-read-only (get-identity-access-stats (identity-id uint))
  (match (map-get? patient-identities { identity-id: identity-id })
    identity (ok {
      total-accesses: (get access-count identity),
      last-accessed: (get last-accessed identity),
      created-block: (get created-block identity),
      consent-expiry: (get consent-expiry identity)
    })
    ERR-IDENTITY-NOT-FOUND))

;; Admin functions
(define-public (set-privacy-enabled (enabled bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-ADMIN) ERR-NOT-AUTHORIZED)
    (var-set privacy-enabled enabled)
    (ok enabled)))

(define-public (update-encryption-key (new-key-hash (buff 32)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-ADMIN) ERR-NOT-AUTHORIZED)
    (var-set encryption-key-hash new-key-hash)
    (ok true)))

(define-read-only (get-system-status)
  {
    privacy-enabled: (var-get privacy-enabled),
    total-identities: (var-get next-identity-id),
    total-audit-entries: (var-get next-audit-id),
    admin: CONTRACT-ADMIN
  })
