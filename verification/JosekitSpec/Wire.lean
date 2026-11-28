import Lean

namespace JosekitSpec

open Lean

inductive Compact where
  | jws (protectedHeader payload signature : String)
  | jwe (protectedHeader encryptedKey iv ciphertext tag : String)
  deriving DecidableEq, Repr

namespace Compact

def parts : Compact → List String
  | .jws header payload signature => [header, payload, signature]
  | .jwe header key iv ciphertext tag => [header, key, iv, ciphertext, tag]

def ofParts : List String → Option Compact
  | [header, payload, signature] => some (.jws header payload signature)
  | [header, key, iv, ciphertext, tag] => some (.jwe header key iv ciphertext tag)
  | _ => none

def parse (wire : String) : Option Compact :=
  ofParts (wire.splitOn ".")

@[simp] theorem ofParts_parts (token : Compact) : ofParts token.parts = some token := by
  cases token <;> rfl

theorem parts_length (token : Compact) : token.parts.length = 3 ∨ token.parts.length = 5 := by
  cases token <;> simp [parts]

theorem parts_of_success {segments : List String} {token : Compact}
    (h : ofParts segments = some token) : token.parts = segments := by
  unfold ofParts at h
  split at h <;> cases h <;> rfl

theorem parse_parts {wire : String} {token : Compact} (h : parse wire = some token) :
    token.parts = wire.splitOn "." :=
  parts_of_success h

end Compact

def base64urlSextet (c : Char) : Option Nat :=
  if 'A' ≤ c ∧ c ≤ 'Z' then some (c.toNat - 'A'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'z' then some (c.toNat - 'a'.toNat + 26)
  else if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat + 52)
  else if c = '-' then some 62
  else if c = '_' then some 63
  else none

def Base64urlChar (c : Char) : Prop :=
  ('A' ≤ c ∧ c ≤ 'Z') ∨ ('a' ≤ c ∧ c ≤ 'z') ∨ ('0' ≤ c ∧ c ≤ '9') ∨ c = '-' ∨ c = '_'

private theorem sextet_isSome (c : Char) :
    (base64urlSextet c).isSome = true ↔ Base64urlChar c := by
  unfold base64urlSextet Base64urlChar
  repeat (first | split | simp_all)

/-- A canonical stream has full groups followed by zero, one or two bytes'
    worth of sextets. The unused low bits of a partial group must be zero. -/
inductive CanonicalSextets : List Nat → Prop where
  | empty : CanonicalSextets []
  | two {a b : Nat} : b % 16 = 0 → CanonicalSextets [a, b]
  | three {a b c : Nat} : c % 4 = 0 → CanonicalSextets [a, b, c]
  | group (a b c d : Nat) {tail : List Nat} :
    CanonicalSextets tail → CanonicalSextets (a :: b :: c :: d :: tail)

private def decodeSextets : List Nat → Option (List UInt8)
  | a :: b :: c :: d :: tail => do
    let rest ← decodeSextets tail
    return UInt8.ofNat (a * 4 + b / 16) ::
      UInt8.ofNat (b % 16 * 16 + c / 4) :: UInt8.ofNat (c % 4 * 64 + d) :: rest
  | [a, b, c] =>
    if c % 4 = 0 then some [UInt8.ofNat (a * 4 + b / 16), UInt8.ofNat (b % 16 * 16 + c / 4)]
    else none
  | [a, b] => if b % 16 = 0 then some [UInt8.ofNat (a * 4 + b / 16)] else none
  | [] => some []
  | [_] => none

/-- Unpadded, canonical Base64url. Empty segments decode to zero bytes. -/
def base64url (encoded : String) : Option ByteArray := do
  let values ← encoded.toList.mapM base64urlSextet
  let bytes ← decodeSextets values
  return ⟨bytes.toArray⟩

private theorem decodeSextets_canonical (values : List Nat) :
    (decodeSextets values).isSome = true ↔ CanonicalSextets values := by
  constructor
  · intro h
    induction values using decodeSextets.induct with
    | case1 a b c d tail ih =>
      apply CanonicalSextets.group
      apply ih
      cases ht : decodeSextets tail <;> simp_all [decodeSextets]
    | case2 a b c hc => exact CanonicalSextets.three hc
    | case3 a b c hc => simp [decodeSextets, hc] at h
    | case4 a b hb => exact CanonicalSextets.two hb
    | case5 a b hb => simp [decodeSextets, hb] at h
    | case6 => exact CanonicalSextets.empty
    | case7 a => simp [decodeSextets] at h
  · intro h
    induction h with
    | empty => rfl
    | two hb => simp [decodeSextets, hb]
    | three hc => simp [decodeSextets, hc]
    | group a b c d h ih =>
      rename_i tail
      cases ht : decodeSextets tail <;> simp_all [decodeSextets]

theorem base64url_canonical (encoded : String) :
    (base64url encoded).isSome = true ↔
      ∃ values, encoded.toList.mapM base64urlSextet = some values ∧ CanonicalSextets values := by
  unfold base64url
  cases hs : encoded.toList.mapM base64urlSextet with
  | none => simp [hs]
  | some values =>
    simp only [Option.some.injEq, exists_eq_left']
    rw [← decodeSextets_canonical values]
    cases hd : decodeSextets values <;> simp [hs, hd]

private theorem base64urlChars_of_sextets {chars : List Char} {values : List Nat}
    (h : chars.mapM base64urlSextet = some values) : ∀ c ∈ chars, Base64urlChar c := by
  induction chars generalizing values with
  | nil => simp
  | cons head tail ih =>
    cases hh : base64urlSextet head <;> cases ht : tail.mapM base64urlSextet <;> simp_all [List.mapM_cons]
    exact (sextet_isSome head).mp (by simp [hh])

theorem base64url_alphabet {encoded : String} (h : (base64url encoded).isSome = true) :
    ∀ c ∈ encoded.toList, Base64urlChar c := by
  obtain ⟨_, hm, _⟩ := (base64url_canonical encoded).mp h
  exact base64urlChars_of_sextets hm

def standardBase64 (encoded : String) : Option ByteArray := do
  if encoded.length % 4 != 0 then none else
    let chars := encoded.toList
    let unpadded := (chars.reverse.dropWhile (· == '=')).reverse
    if chars.length - unpadded.length > 2 then none else
      let url := unpadded.mapM fun c => match c with
        | '+' => some '-'
        | '/' => some '_'
        | '-' | '_' => none
        | _ => some c
      base64url (String.mk (← url))

def jsonBytes (bytes : ByteArray) : Option Json := do
  let text ← String.fromUTF8? bytes
  (Json.parse text).toOption

def stringList (value : Json) : Option (List String) := do
  let values ← value.getArr?.toOption
  values.toList.mapM fun item => item.getStr?.toOption

def audienceList (value : Json) : Option (List String) :=
  match value with
  | .str name => some [name]
  | _ => stringList value

/-- Optional fields reject a value of the wrong type and preserve absence. -/
def optionalField {α : Type} (obj : Json) (key : String) (read : Json → Option α) :
    Option (Option α) :=
  match obj.getObjVal? key with
  | .ok value => (read value).map some
  | .error _ => some none

def certificates (value : Json) : Option (List ByteArray) := do
  let certs ← stringList value
  certs.mapM standardBase64

end JosekitSpec
