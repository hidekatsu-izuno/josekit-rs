import Extracted
import JosekitSpec.Jwt

namespace JosekitSpec.Source

open JwkIndex (State)

theorem jwk_new : jwkNew = State.empty := rfl

theorem jwk_get (state : State) (kid : String) : jwkGet state kid = state.get kid := rfl

theorem jwk_push (state : State) (entry : JwkIndex.Entry) :
    jwkPush state entry = state.push entry := by
  unfold jwkPush appendToEntries appendToBucket JwkIndex.State.push
  dsimp only
  apply congrArg (JwkIndex.State.mk (state.entries ++ [entry]))
  funext kid
  by_cases matchKid : entry.key.kid = some kid <;> simp [JwkIndex.matchesKid, matchKid]

private theorem find_eq_index {α : Type} (values : List α) (p : α → Bool) :
    values.find? p = (values.findIdx? p).bind (fun i => values[i]?) := by
  induction values with
  | nil => rfl
  | cons head tail ih =>
    by_cases matchHead : p head
    · simp [List.findIdx?_cons, matchHead]
    · cases found : tail.findIdx? p <;>
        simp [List.findIdx?_cons, matchHead, found, ih]

theorem jwk_remove (state : State) (key : Jwk) :
    jwkRemove state key = state.remove key := by
  unfold jwkRemove JwkIndex.State.remove
  rw [find_eq_index, List.eraseP_eq_eraseIdx]
  change (match state.entries.findIdx? (fun entry => entry.key == key) with
    | none => state
    | some i => retainOtherEntries (eraseEntry state i) state.entries[i]?) =
    (match (state.entries.findIdx? (fun entry => entry.key == key)).bind
        (fun i => state.entries[i]?) with
      | none => state
      | some removed =>
        ⟨(match state.entries.findIdx? (fun entry => entry.key == key) with
            | none => state.entries
            | some i => state.entries.eraseIdx i),
          fun kid => if removed.key.kid == some kid then
            (state.buckets kid).filter (fun entry => entry.id != removed.id)
          else state.buckets kid⟩)
  cases found : state.entries.findIdx? (fun entry => entry.key == key) with
  | none => rfl
  | some index =>
    have inBounds := (List.findIdx?_eq_some_iff_findIdx_eq.mp found).1
    simp only [Option.bind_some, getElem?_pos state.entries index inBounds,
      retainOtherEntries, eraseEntry]

inductive SourceReachable : State → Prop where
  | new : SourceReachable jwkNew
  | push {state : State} (prior : SourceReachable state) (entry : JwkIndex.Entry)
      (fresh : state.Fresh entry) : SourceReachable (jwkPush state entry)
  | remove {state : State} (prior : SourceReachable state) (key : Jwk) :
      SourceReachable (jwkRemove state key)

theorem source_reachable_refines {state : State} (h : SourceReachable state) :
    JwkIndex.Reachable state := by
  induction h with
  | new => rw [jwk_new]; exact .empty
  | push _ entry fresh ih => rw [jwk_push]; exact .push ih entry fresh
  | remove _ key ih => rw [jwk_remove]; exact .remove ih key

theorem jwk_index_after_source_operations {state : State}
    (h : SourceReachable state) (kid : String) : state.Valid ∧ jwkGet state kid = state.keys.get kid :=
  let valid := (source_reachable_refines h).valid
  ⟨valid, jwk_get state kid ▸ JwkIndex.State.get_refines valid kid⟩

theorem jws_tail (header payload signature : ByteArray) (encoded : Bool)
    (decode : ByteArray → Option ByteArray) (verify : ByteArray → ByteArray → Bool) :
    (jwsTail header payload signature encoded decode verify).outcome =
      CompactFlow.jwsBytes header payload signature encoded decode verify := by
  unfold jwsTail CompactFlow.jwsBytes
  cases sig : decode signature with
  | none => rfl
  | some bytes =>
    cases verified : verify (CompactFlow.jwsInputBytes header payload) bytes <;>
      cases encoded <;> cases decoded : decode payload <;>
      simp [verified, Bind.bind, Trace.bind, liftOption, event, Trace.outcome]

theorem jws_tail_refines_text (header payload signature : String) (encoded : Bool)
    (decode : ByteArray → Option ByteArray) (verify : ByteArray → ByteArray → Bool)
    (decodeSig : decode signature.toUTF8 = base64url signature)
    (decodePayload : encoded = true → decode payload.toUTF8 = base64url payload) :
    (jwsTail header.toUTF8 payload.toUTF8 signature.toUTF8 encoded decode verify).result =
      (CompactFlow.jws header payload signature encoded (fun msg => verify msg.toUTF8)).payload := by
  have trace := congrArg CompactFlow.Outcome.payload
    (jws_tail header.toUTF8 payload.toUTF8 signature.toUTF8 encoded decode verify)
  rw [show (jwsTail header.toUTF8 payload.toUTF8 signature.toUTF8 encoded decode verify).result =
    (jwsTail header.toUTF8 payload.toUTF8 signature.toUTF8 encoded decode verify).outcome.payload
    from rfl, trace]
  unfold CompactFlow.jwsBytes CompactFlow.jws
  rw [decodeSig]
  simp only [CompactFlow.jwsInputBytes_text]
  cases encoded with
  | false => cases base64url signature <;> rfl
  | true =>
    rw [decodePayload rfl]
    cases base64url signature <;> rfl

theorem jwe_tail (header encrypted iv ciphertext tag : String) (keySize : Nat)
    (unwrap : Option ByteArray → Option ByteArray)
    (authenticate : ByteArray → Option ByteArray → ByteArray → String → Option ByteArray →
      Option ByteArray)
    (decompress : Option (ByteArray → Option ByteArray)) :
    (jweTail header encrypted iv ciphertext tag keySize unwrap authenticate decompress).outcome =
      CompactFlow.jwe header encrypted iv ciphertext tag keySize unwrap authenticate decompress := by
  unfold jweTail CompactFlow.jwe
  cases parsed : PreparedJwe.read header encrypted iv ciphertext tag with
  | none => rfl
  | some packet =>
    cases key : unwrap (CompactFlow.optionalSegment packet.encryptedKey) with
    | none => simp [key, Bind.bind, Trace.bind, liftOption, event, Trace.outcome]
    | some cek =>
      by_cases size : cek.size = keySize
      · cases auth : authenticate cek (CompactFlow.optionalSegment packet.iv) packet.ciphertext
          packet.aad (CompactFlow.optionalSegment packet.tag) <;>
          cases decompress <;> simp [key, size, auth, Bind.bind, Pure.pure,
            Trace.bind, Trace.pure, liftOption, event, Trace.outcome]
        split <;> simp_all
      · simp [key, size, Bind.bind, Trace.bind, liftOption, event, Trace.outcome]

theorem gcm_guards (iv : Option ByteArray) (tag : ByteArray) :
    (gcmGuards iv tag).isSome = true ↔
      tag.size = 16 ∧ ∃ bytes, iv = some bytes ∧ bytes.size = 12 := by
  cases iv with
  | none =>
    have emptySize : ByteArray.empty.size = 0 := rfl
    simp [gcmGuards, emptySize]
  | some bytes =>
    by_cases validTag : tag.size = 16 <;> by_cases validIv : bytes.size = 12 <;>
      simp [gcmGuards, validTag, validIv]

theorem jwt_header_guard (critical : Option (List String)) :
    jwtHeaderGuard critical = true ↔ "b64" ∉ critical.getD [] := by
  cases critical <;> simp [jwtHeaderGuard, Option.any]

theorem numeric_date_iff (number : Option (Option Nat × Option Nat))
    (checkedAdd : Nat → Option α) (value : α) :
    numericDate number checkedAdd = some value ↔
      ∃ wholeSeconds floatDuration nanos, number = some (wholeSeconds, floatDuration) ∧
        (wholeSeconds.map (1000000000 * ·)).or floatDuration = some nanos ∧
          checkedAdd nanos = some value := by
  change (number.bind fun (wholeSeconds, floatDuration) =>
    ((wholeSeconds.map (1000000000 * ·)).or floatDuration).bind checkedAdd) = some value ↔ _
  simp only [Option.bind_eq_some_iff]
  constructor
  · rintro ⟨⟨wholeSeconds, floatDuration⟩, found, nanos, duration, added⟩
    exact ⟨wholeSeconds, floatDuration, nanos, found, duration, added⟩
  · rintro ⟨wholeSeconds, floatDuration, nanos, found, duration, added⟩
    exact ⟨(wholeSeconds, floatDuration), found, nanos, duration, added⟩

theorem numeric_date_integer_refines (maxDateNanos seconds : Nat) (floatDuration : Option Nat) :
    numericDate (some (some seconds, floatDuration))
        (fun nanos => if nanos ≤ maxDateNanos then some (nanos : Int) else none) =
      readNumericDate maxDateNanos (.num (Lean.JsonNumber.fromNat seconds)) := by
  have rounded : numericDateNanos (Lean.JsonNumber.fromNat seconds) =
      ((1000000000 * seconds : Nat) : Int) := by
    simp only [numericDateNanos, Lean.JsonNumber.fromNat, Int.natCast_mul] <;> rfl
  change (if 1000000000 * seconds ≤ maxDateNanos then
      some ((1000000000 * seconds : Nat) : Int) else none) = (if
        0 ≤ (seconds : Int) ∧ numericDateNanos (Lean.JsonNumber.fromNat seconds) ≤ (maxDateNanos : Int)
        then some (numericDateNanos (Lean.JsonNumber.fromNat seconds)) else none)
  simp only [rounded, Int.natCast_nonneg, true_and, Int.ofNat_le]

end JosekitSpec.Source
