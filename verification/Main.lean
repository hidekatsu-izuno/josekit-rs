import JosekitSpec

open Lean JosekitSpec

private def field [FromJson α] (value : Json) (name : String) : Except String α :=
  value.getObjValAs? α name

private def bytesJson (bytes : ByteArray) : Json :=
  toJson (bytes.data.map UInt8.toNat)

private def readBytes (value : Option (Array Nat)) : Option ByteArray :=
  value.map (fun bytes => ⟨bytes.map UInt8.ofNat⟩)

private def outcome (calls : List Json) (payload : Option ByteArray) : Json :=
  Json.mkObj [("calls", toJson calls), ("payload", toJson (payload.map bytesJson))]

private def jweCallJson : CompactFlow.JweCall → Json
  | .unwrapKey key => toJson [toJson "unwrap", toJson (key.map bytesJson)]
  | .authenticate key iv ciphertext aad tag =>
    toJson [toJson "authenticate", bytesJson key, toJson (iv.map bytesJson),
      bytesJson ciphertext, bytesJson aad.toUTF8, toJson (tag.map bytesJson)]
  | .decompress bytes => toJson [toJson "decompress", bytesJson bytes]

private def sameJwePacket (left right : PreparedJwe) : Bool :=
  left.aad == right.aad &&
    left.encryptedKey.data == right.encryptedKey.data &&
    left.iv.data == right.iv.data &&
    left.ciphertext.data == right.ciphertext.data &&
    left.tag.data == right.tag.data

private def referenceVerifier (reference : String) : String → ByteArray → Bool :=
  fun input signature =>
    match Compact.parse reference with
    | some (.jws header payload encoded) =>
      input == header ++ "." ++ payload &&
        ((base64url encoded).map ByteArray.data) == some signature.data
    | _ => false

private def referenceDecrypter (reference : String) (payload : Option (Array Nat)) :
    PreparedJwe → Option ByteArray := fun packet => do
  let .jwe header key iv ciphertext tag ← Compact.parse reference | none
  let segments ← [key, iv, ciphertext, tag].mapM base64url
  let actual := [packet.encryptedKey, packet.iv, packet.ciphertext, packet.tag]
  if packet.aad == header && segments.map ByteArray.data == actual.map ByteArray.data then
    readBytes payload
  else none

private def keySetTrace (input : Json) : Except String Json := do
  let initial : Json ← field input "initial"
  let some initial := KeySet.read initial | throw "invalid initial key set"
  let queries : List String ← field input "queries"
  let ops : Array Json ← field input "operations"
  let mut keys := initial.zipIdx.foldl
    (fun state (key, id) => JwkIndex.State.push state ⟨id, key⟩) JwkIndex.State.empty
  let mut snapshots := #[]
  for (op, id) in ops.toList.zipIdx do
    let action : String ← field op "action"
    if action != "inspect" then
      let value : Json ← field op "key"
      let some key := Jwk.read value | throw "invalid key in an operation"
      keys ← match action with
        | "push" => pure (keys.push ⟨initial.length + id, key⟩)
        | "remove" => pure (keys.remove key)
        | _ => throw ("unknown key set operation: " ++ action)
    let values := toJson (keys.keys.map Jwk.value)
    let found := queries.map fun kid => toJson ((keys.get kid).map Jwk.value)
    snapshots := snapshots.push (Json.mkObj [
      ("keys", values),
      ("mapKeys", values),
      ("displayKeys", values),
      ("lookups", toJson found)])
  return toJson snapshots

private def expected (maxDateNanos : Nat) (input : Json) : Except String Json := do
  match ← field (α := String) input "kind" with
  | "inspect" =>
    return toJson ((inspectHeader (← field input "wire")).map Header.value)
  | "jws" =>
    let wire ← field input "wire"
    let policy ← field input "policy"
    let reference := referenceVerifier (← field input "reference")
    if ← field (α := Bool) input "jwt" then
      return toJson ((decodeSignedJwt maxDateNanos wire policy reference).map Claims.value)
    else
      return toJson ((verifyJws wire policy false reference).map bytesJson)
  | "jwe" =>
    let wire ← field input "wire"
    let policy : DecryptionPolicy := { toVerificationPolicy := ← field input "policy" }
    let reference := referenceDecrypter (← field input "reference") (← field input "plaintext")
    if ← field (α := Bool) input "jwt" then
      return toJson ((decodeEncryptedJwt maxDateNanos wire policy reference).map Claims.value)
    else
      return toJson ((decryptJwe wire policy reference).map bytesJson)
  | "jwsFlow" =>
    let some (.jws header payload signature) := Compact.parse (← field input "wire")
      | throw "expected Compact JWS framing"
    let accepts ← field input "accepts"
    let result := CompactFlow.jws header payload signature true (fun _ _ => accepts)
    return outcome (result.calls.map fun (message, sig) =>
      toJson [toJson "verify", bytesJson message.toUTF8, bytesJson sig]) result.payload
  | "jweFlow" =>
    let some (.jwe header key iv ciphertext tag) := Compact.parse (← field input "wire")
      | throw "expected Compact JWE framing"
    let keySize ← field input "keySize"
    let cek := readBytes (← field input "key")
    let plaintext := readBytes (← field input "plaintext")
    let decompressed := readBytes (← field input "decompressed")
    let zip ← field (α := Bool) input "zip"
    let result := CompactFlow.jwe header key iv ciphertext tag keySize (fun _ => cek)
      (fun _ _ _ _ _ => plaintext) (if zip then some (fun _ => decompressed) else none)
    return outcome (result.calls.map jweCallJson) result.payload
  | "jsonJws" =>
    let wire ← field input "wire"
    let reference ← field input "reference"
    let policy ← field input "policy"
    let payload := do
      let packet ← prepareJsonJws wire policy >>= List.head?
      let original ← prepareJsonJws reference policy >>= List.head?
      if packet.signingInput == original.signingInput &&
          packet.signature.data == original.signature.data then some packet.payload else none
    return toJson (payload.map bytesJson)
  | "jsonJwe" =>
    let wire ← field input "wire"
    let reference ← field input "reference"
    let policy : DecryptionPolicy := { toVerificationPolicy := ← field input "policy" }
    let plaintext : Array Nat ← field input "plaintext"
    let payload := do
      let packet ← prepareJsonJwe wire policy >>= List.head?
      let original ← prepareJsonJwe reference policy >>= List.head?
      if sameJwePacket packet original then some plaintext else none
    return toJson payload
  | "claims" =>
    let claims : Json ← field input "claims"
    let policy ← field input "policy"
    return toJson ((Claims.read maxDateNanos claims).any (·.accepts policy))
  | "numericDate" =>
    let claim : Json ← field input "value"
    return toJson ((readNumericDate maxDateNanos claim).map toString)
  | "jwk" =>
    let value : Json ← field input "value"
    return toJson (Jwk.read value).isSome
  | "base64url" =>
    let encoded : String ← field input "encoded"
    return toJson ((base64url encoded).map bytesJson)
  | "keySet" =>
    let value : Json ← field input "value"
    return toJson (KeySet.read value).isSome
  | "keySetTrace" => keySetTrace input
  | kind => throw ("unknown case kind: " ++ kind)

private def describeDifference (expected actual : Json) : String :=
  match expected, actual with
  | .arr exp, .arr got =>
    if exp.size == got.size then
      match (List.range exp.size).find? (fun i => exp[i]? != got[i]?) with
      | some i => s!"at index {i}: Lean expects {(exp[i]!).compress}, Rust returned {(got[i]!).compress}"
      | none => s!"Lean expects {expected.compress}, Rust returned {actual.compress}"
    else s!"Lean expects {exp.size} entries, Rust returned {got.size}"
  | _, _ => s!"Lean expects {expected.compress}, Rust returned {actual.compress}"

def main : IO UInt32 := do
  let input ← (← IO.getStdin).getLine
  let .ok request := Json.parse input
    | IO.eprintln "expected a JSON object of Rust API observations"; return 2
  let .ok limit := field (α := String) request "maxDateNanos"
    | IO.eprintln "expected a target NumericDate limit"; return 2
  let some maxDateNanos := limit.toNat?
    | IO.eprintln "expected a nonnegative NumericDate limit"; return 2
  let .ok cases := field (α := Array Json) request "cases"
    | IO.eprintln "expected a JSON array of Rust API observations"; return 2
  if cases.isEmpty then
    IO.eprintln "no Rust API observations"
    return 2
  let mut failures := 0
  for sample in cases do
    let name := (field (α := String) sample "name").toOption.getD "<unknown case>"
    match expected maxDateNanos sample, field (α := Json) sample "actual" with
    | .ok spec, .ok actual =>
      if spec != actual then
        failures := failures + 1
        IO.eprintln s!"{name}: {describeDifference spec actual}"
    | .error err, _ | _, .error err =>
      failures := failures + 1
      IO.eprintln s!"{name}: invalid observation: {err}"
  IO.println s!"Lean/Rust conformance: {cases.size - failures}/{cases.size} observations passed"
  return if failures == 0 then 0 else 1
