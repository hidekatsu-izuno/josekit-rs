import JosekitSpec.Jwk

namespace JosekitSpec

open Lean

structure Header where
  alg : Option String
  kid : Option String
  crit : List String
  b64 : Option Bool
  enc : Option String
  zip : Option String
  value : Json

/-- Project the fields used by the compact protocol from a decoded JSON object. -/
def Header.read (encrypted : Bool) (value : Json) : Option Header := do
  let _ ← value.getObj?.toOption
  let text := fun v : Json => v.getStr?.toOption
  let alg ← optionalField value "alg" text
  let kid ← optionalField value "kid" text
  let crit ← optionalField value "crit" stringList
  let b64 := (value.getObjVal? "b64").toOption.bind fun v => v.getBool?.toOption
  for field in ["jku", "x5u", "typ", "cty", "url"] do
    let _ ← optionalField value field text
  for field in (if encrypted then ["x5t", "x5t#S256", "nonce", "apu", "apv"]
      else ["x5t", "x5t#S256", "nonce"]) do
    let _ ← optionalField value field (fun v => text v >>= base64url)
  let _ ← optionalField value "x5c" certificates
  let _ ← optionalField value "jwk" Jwk.read
  if encrypted then
    let _ ← optionalField value "iss" text
    let _ ← optionalField value "sub" text
    let _ ← optionalField value "aud" audienceList
  let enc ← if encrypted then optionalField value "enc" text else some none
  let zip ← if encrypted then optionalField value "zip" text else some none
  if !encrypted && b64 == some false && (crit.any fun names => !names.contains "b64") then
    none
  else
    some ⟨alg, kid, crit.getD [], b64, enc, zip, value⟩

def Header.decode (encrypted : Bool) (segment : String) : Option Header :=
  (base64url segment >>= jsonBytes) >>= Header.read encrypted

/-- Header inspection requires valid framing and a header. It never authenticates the token. -/
def inspectHeader (wire : String) : Option Header := do
  match ← Compact.parse wire with
  | .jws header .. => Header.decode false header
  | .jwe header .. => Header.decode true header

structure VerificationPolicy where
  alg : String
  kid : Option String := none
  critical : List String := []
  deriving FromJson

def VerificationPolicy.allows (policy : VerificationPolicy) (header : Header)
    (allowMissingKid : Bool) : Bool :=
  header.alg == some policy.alg &&
    (policy.kid.isNone || header.kid == policy.kid || (allowMissingKid && header.kid.isNone)) &&
    header.crit.all policy.critical.contains

theorem VerificationPolicy.allows_iff (policy : VerificationPolicy) (header : Header)
    (allowMissingKid : Bool) : policy.allows header allowMissingKid = true ↔
    header.alg = some policy.alg ∧
    (policy.kid = none ∨ header.kid = policy.kid ∨ (allowMissingKid = true ∧ header.kid = none)) ∧
    ∀ name ∈ header.crit, name ∈ policy.critical := by
  simp [allows, and_assoc, or_assoc]

structure PreparedJws where
  signingInput : String
  signature : ByteArray
  payload : ByteArray

/-- JWT does not permit the JWS b64 critical extension. -/
def prepareJws (wire : String) (policy : VerificationPolicy) (jwt : Bool) :
    Option PreparedJws := do
  let .jws protectedHeader payload signature ← Compact.parse wire | none
  let header ← Header.decode false protectedHeader
  if !policy.allows header false || (jwt && header.crit.contains "b64") then
    none
  else
    let data := if header.crit.contains "b64" && header.b64 == some false then
      some payload.toUTF8
    else base64url payload
    return ⟨protectedHeader ++ "." ++ payload, ← base64url signature, ← data⟩

def verifyJws (wire : String) (policy : VerificationPolicy) (jwt : Bool)
    (verify : String → ByteArray → Bool) : Option ByteArray := do
  let prepared ← prepareJws wire policy jwt
  if verify prepared.signingInput prepared.signature then some prepared.payload else none

theorem verifyJws_authenticated {wire policy jwt verify payload}
    (h : verifyJws wire policy jwt verify = some payload) :
    ∃ prepared, prepareJws wire policy jwt = some prepared ∧
      verify prepared.signingInput prepared.signature = true ∧ prepared.payload = payload := by
  unfold verifyJws at h
  cases hp : prepareJws wire policy jwt with
  | none => simp [hp] at h
  | some prepared =>
    cases hv : verify prepared.signingInput prepared.signature <;> simp_all

theorem prepareJws_original_input {wire policy jwt prepared}
    (h : prepareJws wire policy jwt = some prepared) :
    ∃ header payload signature, Compact.parse wire = some (.jws header payload signature) ∧
      prepared.signingInput = header ++ "." ++ payload := by
  unfold prepareJws at h
  cases hp : Compact.parse wire with
  | none => simp [hp] at h
  | some token =>
    cases token with
    | jwe => simp [hp] at h
    | jws header payload signature =>
      refine ⟨header, payload, signature, rfl, ?_⟩
      simp only [hp, Bind.bind, Option.bind] at h
      split at h
      · contradiction
      · dsimp only at h
        split at h
        · contradiction
        · split at h <;> try contradiction
          dsimp only at h
          split at h <;> try contradiction
          cases h
          rfl

structure DecryptionPolicy extends VerificationPolicy where
  contentEncryptions : List String :=
    ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]
  compressions : List String := ["DEF"]

def DecryptionPolicy.allows (policy : DecryptionPolicy) (header : Header) : Bool :=
  policy.toVerificationPolicy.allows header true &&
    header.enc.any policy.contentEncryptions.contains &&
    header.zip.all policy.compressions.contains

structure PreparedJwe where
  aad : String
  encryptedKey : ByteArray
  iv : ByteArray
  ciphertext : ByteArray
  tag : ByteArray

def PreparedJwe.read (aad key iv ciphertext tag : String) : Option PreparedJwe :=
  (base64url key).bind fun keyBytes =>
    (base64url iv).bind fun ivBytes =>
      (base64url ciphertext).bind fun ciphertextBytes =>
        (base64url tag).map fun tagBytes => ⟨aad, keyBytes, ivBytes, ciphertextBytes, tagBytes⟩

theorem PreparedJwe.read_aad {aad key iv ciphertext tag packet}
    (h : read aad key iv ciphertext tag = some packet) : packet.aad = aad := by
  simp only [read, Option.bind_eq_some, Option.map_eq_bind, Function.comp_apply] at h
  obtain ⟨_, _, _, _, _, _, _, _, heq⟩ := h
  cases heq
  rfl

def contentParameterSizes : Option String → Option (Nat × Nat)
  | some "A128GCM" | some "A192GCM" | some "A256GCM" => some (12, 16)
  | some "A128CBC-HS256" => some (16, 16)
  | some "A192CBC-HS384" => some (16, 24)
  | some "A256CBC-HS512" => some (16, 32)
  | _ => none

/-- The built-in content encryption names determine the required IV and tag lengths. -/
def PreparedJwe.hasParameters (packet : PreparedJwe) (policy : DecryptionPolicy)
    (header : Header) : Bool :=
  (policy.alg != "dir" || packet.encryptedKey.size == 0) &&
    (contentParameterSizes header.enc).all
      (fun (iv, tag) => packet.iv.size == iv && packet.tag.size == tag)

theorem PreparedJwe.hasParameters_iff (packet : PreparedJwe) (policy : DecryptionPolicy)
    (header : Header) : packet.hasParameters policy header = true ↔
    (policy.alg = "dir" → packet.encryptedKey.size = 0) ∧
    ∀ lengths ∈ contentParameterSizes header.enc,
      packet.iv.size = lengths.1 ∧ packet.tag.size = lengths.2 := by
  by_cases direct : policy.alg = "dir" <;> cases h : contentParameterSizes header.enc <;>
    simp [hasParameters, direct, h, Option.all, and_assoc]

theorem PreparedJwe.gcm_requires_iv_and_tag {packet : PreparedJwe} {policy : DecryptionPolicy}
    {header : Header}
    (enc : header.enc = some "A128GCM" ∨ header.enc = some "A192GCM" ∨ header.enc = some "A256GCM")
    (valid : packet.hasParameters policy header = true) :
    packet.iv.size = 12 ∧ packet.tag.size = 16 :=
  ((packet.hasParameters_iff policy header).mp valid).2 (12, 16)
    (by rcases enc with enc | enc | enc <;> simp [enc, contentParameterSizes])

def prepareJwe (wire : String) (policy : DecryptionPolicy) : Option PreparedJwe := do
  let .jwe protectedHeader key iv ciphertext tag ← Compact.parse wire | none
  let header ← Header.decode true protectedHeader
  let packet ← PreparedJwe.read protectedHeader key iv ciphertext tag
  if policy.allows header && packet.hasParameters policy header then some packet else none

theorem prepareJwe_original_aad {wire policy packet}
    (h : prepareJwe wire policy = some packet) :
    ∃ header key iv ciphertext tag, Compact.parse wire = some (.jwe header key iv ciphertext tag) ∧
      packet.aad = header := by
  change (Compact.parse wire).bind _ = some packet at h
  obtain ⟨token, ht, h⟩ := Option.bind_eq_some.mp h
  cases token with
  | jws => simp at h
  | jwe header key iv ciphertext tag =>
    refine ⟨header, key, iv, ciphertext, tag, ht, ?_⟩
    change (Header.decode true header).bind _ = some packet at h
    obtain ⟨_, _, h⟩ := Option.bind_eq_some.mp h
    obtain ⟨_, prepared, h⟩ := Option.bind_eq_some.mp h
    split at h
    · cases h
      exact PreparedJwe.read_aad prepared
    · contradiction

/-- The callback unwraps the key and authenticates the ciphertext before exposing plaintext. -/
def decryptJwe (wire : String) (policy : DecryptionPolicy)
    (openPacket : PreparedJwe → Option ByteArray) : Option ByteArray :=
  prepareJwe wire policy >>= openPacket

theorem decryptJwe_authenticated {wire policy openPacket plaintext}
    (h : decryptJwe wire policy openPacket = some plaintext) :
    ∃ prepared, prepareJwe wire policy = some prepared ∧ openPacket prepared = some plaintext := by
  unfold decryptJwe at h
  cases hp : prepareJwe wire policy <;> simp_all

end JosekitSpec
