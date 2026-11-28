import JosekitSpec.Compact

namespace JosekitSpec.CompactFlow

structure Outcome (Event : Type) where
  calls : List Event
  payload : Option ByteArray

def jwsInputBytes (header payload : ByteArray) : ByteArray :=
  header ++ ⟨#[46]⟩ ++ payload

theorem jwsInputBytes_text (header payload : String) :
    jwsInputBytes header.toUTF8 payload.toUTF8 = (header ++ "." ++ payload).toUTF8 := by
  simp only [jwsInputBytes, String.toUTF8, String.toByteArray_append]
  rfl

/-- The raw byte form also covers unencoded payloads that are not UTF-8. -/
def jwsBytes (header payload signature : ByteArray) (encoded : Bool)
    (decode : ByteArray → Option ByteArray) (verify : ByteArray → ByteArray → Bool) :
    Outcome (ByteArray × ByteArray) :=
  match decode signature with
  | none => ⟨[], none⟩
  | some sig =>
    let input := jwsInputBytes header payload
    ⟨[(input, sig)], if verify input sig then
      if encoded then decode payload else some payload
      else none⟩

/-- Compact JWS after framing, header validation and verifier selection. -/
def jws (header payload signature : String) (encoded : Bool)
    (verify : String → ByteArray → Bool) : Outcome (String × ByteArray) :=
  match base64url signature with
  | none => ⟨[], none⟩
  | some sig =>
    let input := header ++ "." ++ payload
    ⟨[(input, sig)], if verify input sig then
      if encoded then base64url payload else some payload.toUTF8
      else none⟩

theorem jws_success {header payload signature encoded verify plaintext}
    (h : (jws header payload signature encoded verify).payload = some plaintext) :
    ∃ sig, base64url signature = some sig ∧
      (jws header payload signature encoded verify).calls = [(header ++ "." ++ payload, sig)] ∧
      verify (header ++ "." ++ payload) sig = true := by
  unfold jws at h ⊢
  cases hs : base64url signature with
  | none => simp [hs] at h
  | some sig =>
    refine ⟨sig, rfl, rfl, ?_⟩
    cases hv : verify (header ++ "." ++ payload) sig <;> simp_all

theorem jws_refines {wire policy jwt protectedHeader payload signature header verify}
    (framed : Compact.parse wire = some (.jws protectedHeader payload signature))
    (decoded : Header.decode false protectedHeader = some header)
    (allowed : policy.allows header false = true)
    (extension : jwt = true → "b64" ∉ header.crit) :
    (jws protectedHeader payload signature
        (!(header.crit.contains "b64" && header.b64 == some false)) verify).payload =
      verifyJws wire policy jwt verify := by
  have permitted : (jwt && header.crit.contains "b64") = false := by
    cases jwt <;> simp_all
  unfold verifyJws prepareJws jws
  simp only [framed, decoded, allowed, permitted, Bool.not_true, Bool.false_or,
    Bind.bind, Option.bind]
  cases raw : (header.crit.contains "b64" && header.b64 == some false)
  · cases hs : base64url signature <;> cases hp : base64url payload <;> simp [*]
  · cases hs : base64url signature <;> simp [*]

inductive JweCall where
  | unwrapKey (encryptedKey : Option ByteArray)
  | authenticate (key : ByteArray) (iv : Option ByteArray) (ciphertext : ByteArray)
      (aad : String) (tag : Option ByteArray)
  | decompress (authenticatedPlaintext : ByteArray)

def optionalSegment (bytes : ByteArray) : Option ByteArray :=
  if bytes.isEmpty then none else some bytes

/-- Compact JWE after framing, header validation and algorithm selection. -/
def jwe (header key iv ciphertext tag : String) (keySize : Nat)
    (unwrap : Option ByteArray → Option ByteArray)
    (authenticate : ByteArray → Option ByteArray → ByteArray → String → Option ByteArray →
      Option ByteArray)
    (decompress : Option (ByteArray → Option ByteArray)) : Outcome JweCall :=
  match PreparedJwe.read header key iv ciphertext tag with
  | none => ⟨[], none⟩
  | some packet =>
    let encryptedKey := optionalSegment packet.encryptedKey
    let unwrapCall := JweCall.unwrapKey encryptedKey
    match unwrap encryptedKey with
    | none => ⟨[unwrapCall], none⟩
    | some cek =>
      if cek.size != keySize then ⟨[unwrapCall], none⟩ else
        let iv := optionalSegment packet.iv
        let tag := optionalSegment packet.tag
        let authCall := JweCall.authenticate cek iv packet.ciphertext packet.aad tag
        match authenticate cek iv packet.ciphertext packet.aad tag with
        | none => ⟨[unwrapCall, authCall], none⟩
        | some plaintext =>
          match decompress with
          | none => ⟨[unwrapCall, authCall], some plaintext⟩
          | some f => ⟨[unwrapCall, authCall, .decompress plaintext], f plaintext⟩

theorem jwe_success {header key iv ciphertext tag keySize unwrap authenticate decompress plaintext}
    (h : (jwe header key iv ciphertext tag keySize unwrap authenticate decompress).payload =
      some plaintext) :
    ∃ packet cek authenticated,
      PreparedJwe.read header key iv ciphertext tag = some packet ∧
      unwrap (optionalSegment packet.encryptedKey) = some cek ∧ cek.size = keySize ∧
      authenticate cek (optionalSegment packet.iv) packet.ciphertext header (optionalSegment packet.tag) =
        some authenticated ∧
      (match decompress with
        | none => some authenticated
        | some f => f authenticated) = some plaintext := by
  unfold jwe at h
  cases hp : PreparedJwe.read header key iv ciphertext tag with
  | none => simp [hp] at h
  | some packet =>
    have aad := PreparedJwe.read_aad hp
    cases hk : unwrap (optionalSegment packet.encryptedKey) with
    | none => simp [hp, hk] at h
    | some cek =>
      by_cases size : cek.size = keySize
      · cases ha : authenticate cek (optionalSegment packet.iv) packet.ciphertext packet.aad
          (optionalSegment packet.tag) with
        | none => simp [hp, hk, size, ha] at h
        | some authenticated =>
          refine ⟨packet, cek, authenticated, rfl, hk, size, ?_, ?_⟩
          · simpa only [aad] using ha
          · cases decompress <;> simpa [hp, hk, size, ha] using h
      · simp [hp, hk, size] at h

theorem jwe_authentication_failure {header key iv ciphertext tag keySize unwrap authenticate
    decompress packet cek}
    (hp : PreparedJwe.read header key iv ciphertext tag = some packet)
    (hk : unwrap (optionalSegment packet.encryptedKey) = some cek) (size : cek.size = keySize)
    (failure : authenticate cek (optionalSegment packet.iv) packet.ciphertext header (optionalSegment packet.tag) =
      none) :
    jwe header key iv ciphertext tag keySize unwrap authenticate decompress =
      ⟨[.unwrapKey (optionalSegment packet.encryptedKey),
        .authenticate cek (optionalSegment packet.iv) packet.ciphertext header (optionalSegment packet.tag)],
        none⟩ := by
  simp [jwe, hp, hk, size, PreparedJwe.read_aad hp, failure]

end JosekitSpec.CompactFlow
