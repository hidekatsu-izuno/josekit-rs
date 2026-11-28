import JosekitSpec.Compact

namespace JosekitSpec

open Lean

/-- Normalize an exact decimal NumericDate to nanoseconds. -/
def numericDateNanos (number : JsonNumber) : Int :=
  if number.exponent = 0 then 1000000000 * number.mantissa else
    let denominator : Int := 10 ^ number.exponent
    (2 * number.mantissa * 1000000000 + denominator) / (2 * denominator)

/-- The time limit is the target's maximum duration that can be added to the Unix epoch. -/
def readNumericDate (maxDateNanos : Nat) (value : Json) : Option Int := do
  let number ← value.getNum?.toOption
  let nanos := numericDateNanos number
  if 0 ≤ number.mantissa ∧ nanos ≤ maxDateNanos then some nanos else none

theorem readNumericDate_iff (maxDateNanos : Nat) (number : JsonNumber) (nanos : Int) :
    readNumericDate maxDateNanos (.num number) = some nanos ↔
      0 ≤ number.mantissa ∧ numericDateNanos number ≤ maxDateNanos ∧
        nanos = numericDateNanos number := by
  change (if 0 ≤ number.mantissa ∧ numericDateNanos number ≤ (maxDateNanos : Int) then
    some (numericDateNanos number) else none) = some nanos ↔ _
  by_cases bound : 0 ≤ number.mantissa ∧ numericDateNanos number ≤ (maxDateNanos : Int) <;>
    simp [bound, ← and_assoc, eq_comm]

structure Claims where
  value : Json
  notBefore : Option Int
  expiresAt : Option Int
  issuedAt : Option Int
  audience : Option (List String)

/-- Read the JWT Claims Set after JSON parsing, including its registered claim types. -/
def Claims.read (maxDateNanos : Nat) (obj : Json) : Option Claims := do
  let _ ← obj.getObj?.toOption
  let text := fun v : Json => v.getStr?.toOption
  let _ ← optionalField obj "iss" text
  let _ ← optionalField obj "sub" text
  let _ ← optionalField obj "jti" text
  let date := readNumericDate maxDateNanos
  return ⟨obj, ← optionalField obj "nbf" date, ← optionalField obj "exp" date,
    ← optionalField obj "iat" date, ← optionalField obj "aud" audienceList⟩

def decodeClaims (maxDateNanos : Nat) (bytes : ByteArray) : Option Claims :=
  jsonBytes bytes >>= Claims.read maxDateNanos

def decodeSignedJwt (maxDateNanos : Nat) (wire : String) (policy : VerificationPolicy)
    (verify : String → ByteArray → Bool) : Option Claims :=
  verifyJws wire policy true verify >>= decodeClaims maxDateNanos

def decodeEncryptedJwt (maxDateNanos : Nat) (wire : String) (policy : DecryptionPolicy)
    (openPacket : PreparedJwe → Option ByteArray) : Option Claims :=
  decryptJwe wire policy openPacket >>= decodeClaims maxDateNanos

structure TimePolicy where
  base : Int
  minIssued : Int
  maxIssued : Int
  deriving FromJson

/-- In the time model, bounds and normalized claim values are nanoseconds from the epoch. -/
structure ClaimTimes where
  notBefore : Option Int
  expiresAt : Option Int
  issuedAt : Option Int

def ClaimTimes.valid (times : ClaimTimes) (policy : TimePolicy) : Prop :=
  (∀ n ∈ times.notBefore, n ≤ policy.base) ∧
  (∀ e ∈ times.expiresAt, policy.base < e) ∧
  (∀ i ∈ times.issuedAt, policy.minIssued ≤ i ∧ i ≤ policy.maxIssued)

def ClaimTimes.accepts (times : ClaimTimes) (policy : TimePolicy) : Bool :=
  times.notBefore.all (fun n => n ≤ policy.base) &&
  times.expiresAt.all (fun e => policy.base < e) &&
  times.issuedAt.all (fun i => policy.minIssued ≤ i ∧ i ≤ policy.maxIssued)

theorem ClaimTimes.accepts_iff (times : ClaimTimes) (policy : TimePolicy) :
    times.accepts policy = true ↔ times.valid policy := by
  rcases times with ⟨nbf, exp, iat⟩
  cases nbf <;> cases exp <;> cases iat <;> simp [accepts, valid, Option.all, and_assoc]

theorem expiration_exclusive (times : ClaimTimes) (policy : TimePolicy)
    (h : times.expiresAt = some policy.base) : times.accepts policy = false := by
  have rejected : ¬ times.accepts policy = true := by
    intro accepted
    have valid := (times.accepts_iff policy).mp accepted
    have impossible := valid.2.1 policy.base (by simp [h])
    exact (Int.lt_irrefl _ impossible)
  simp_all

theorem boundaries_accepted (policy : TimePolicy) (issued : Int)
    (lower : policy.minIssued ≤ issued) (upper : issued ≤ policy.maxIssued) :
    (ClaimTimes.mk (some policy.base) (some (policy.base + 1))
      (some issued)).accepts policy = true := by
  rw [ClaimTimes.accepts_iff]
  simp [ClaimTimes.valid, lower, upper]
  omega

structure ClaimsPolicy extends TimePolicy where
  audience : Option String := none
  required : Json := Json.mkObj []
  deriving FromJson

def Claims.times (claims : Claims) : ClaimTimes :=
  ⟨claims.notBefore, claims.expiresAt, claims.issuedAt⟩

def Claims.accepts (claims : Claims) (policy : ClaimsPolicy) : Bool :=
  claims.times.accepts policy.toTimePolicy &&
    policy.audience.all (fun expected => claims.audience.all (·.contains expected)) &&
    (match policy.required.getObj? with
    | .ok fields => fields.toList.all fun (key, value) =>
      (claims.value.getObjVal? key).toOption == some value
    | .error _ => false)

private def MatchingClaims (actual : Json) (fields : List (String × Json)) : Prop :=
  ∀ claim ∈ fields, (actual.getObjVal? claim.1).toOption == some claim.2

private theorem matchingClaims_iff (actual : Json) (fields : List (String × Json)) :
    fields.all (fun claim => (actual.getObjVal? claim.1).toOption == some claim.2) = true ↔
      MatchingClaims actual fields := by
  simp [MatchingClaims]

def Claims.Valid (claims : Claims) (policy : ClaimsPolicy) : Prop :=
  claims.times.valid policy.toTimePolicy ∧
  (∀ expected ∈ policy.audience, ∀ audiences ∈ claims.audience, expected ∈ audiences) ∧
  match policy.required.getObj? with
  | .ok fields => MatchingClaims claims.value fields.toList
  | .error _ => False

theorem Claims.accepts_iff (claims : Claims) (policy : ClaimsPolicy) :
    claims.accepts policy = true ↔ claims.Valid policy := by
  have audience :
      policy.audience.all (fun expected => claims.audience.all (·.contains expected)) = true ↔
      ∀ expected ∈ policy.audience, ∀ audiences ∈ claims.audience, expected ∈ audiences := by
    cases policy.audience <;> cases claims.audience <;> simp [Option.all]
  simp only [accepts, Valid, Bool.and_eq_true, ClaimTimes.accepts_iff, audience, and_assoc]
  cases policy.required.getObj? with
  | ok fields => rw [matchingClaims_iff]
  | error _ => simp

theorem prepareJws_rejects_jwt_b64 {wire policy protectedHeader payload signature header}
    (parsed : Compact.parse wire = some (.jws protectedHeader payload signature))
    (decoded : Header.decode false protectedHeader = some header)
    (critical : "b64" ∈ header.crit) : prepareJws wire policy true = none := by
  simp [prepareJws, parsed, decoded, critical]

end JosekitSpec
