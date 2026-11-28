import JosekitSpec.Compact

namespace JosekitSpec

open Lean

def disjointNames (left right : List String) : Bool :=
  right.all (fun name => !left.contains name)

theorem disjointNames_iff (left right : List String) :
    disjointNames left right = true ↔ ∀ name ∈ right, name ∉ left := by
  simp [disjointNames]

/-- JOSE header objects may be combined only when their member names are disjoint. -/
def mergeHeaders (left right : Json) : Option Json := do
  let first ← left.getObj?.toOption
  let second ← right.getObj?.toOption
  if disjointNames (first.toList.map Prod.fst) (second.toList.map Prod.fst) then
    return .obj (second.foldl (fun acc name value => acc.insert name value) first)
  else none

def jsonAad (protectedHeader external : Option String) : String :=
  protectedHeader.getD "" ++ (external.map ("." ++ ·)).getD ""

/-- With external AAD the separator is present even when the protected header is omitted. -/
theorem jsonAad_external (protectedHeader : Option String) (external : String) :
    jsonAad protectedHeader (some external) = protectedHeader.getD "" ++ ("." ++ external) := rfl

private def emptyObject : Json := Json.mkObj []
private def text (value : Json) : Option String := value.getStr?.toOption

private def readObj (value : Json) : Option Json :=
  value.getObj?.toOption.map fun _ => value

private def encodedHeader (segment : String) : Option Json :=
  base64url segment >>= jsonBytes >>= readObj

private def members (value : Json) (field : String) : Option (List Json) := do
  let _ ← readObj value
  let list ← optionalField value field (fun v => v.getArr?.toOption.map Array.toList)
  match list with
  | none => some [value]
  | some [] => none
  | some items => items.mapM readObj

/-- Parse one signature candidate from flattened or general JSON serialization. -/
def prepareJsonJws (value : Json) (policy : VerificationPolicy) :
    Option (List PreparedJws) := do
  let payload ← (value.getObjVal? "payload").toOption >>= text
  let signatures ← members value "signatures"
  signatures.mapM fun signature => do
    let protectedSegment ← (signature.getObjVal? "protected").toOption >>= text
    let protectedHeader ← encodedHeader protectedSegment
    let unprotected ← optionalField signature "header" readObj
    let unprotected := unprotected.getD emptyObject
    if (unprotected.getObjVal? "crit").isOk then none else
      let merged ← mergeHeaders protectedHeader unprotected >>= Header.read false
      if !policy.allows merged false then none else
        let signatureBytes ← (signature.getObjVal? "signature").toOption >>= text >>= base64url
        let b64 ← if merged.crit.contains "b64" then
          optionalField protectedHeader "b64" (fun v => v.getBool?.toOption)
        else some none
        let payloadBytes ← if b64 == some false then some payload.toUTF8 else base64url payload
        return ⟨protectedSegment ++ "." ++ payload, signatureBytes, payloadBytes⟩

private def nonemptyText (value : Json) : Option String := do
  let value ← text value
  if value.isEmpty then none else some value

private def nonemptyObj (value : Json) : Option Json := do
  let fields ← value.getObj?.toOption
  if fields.isEmpty then none else some value

/-- Parse the recipient candidates using the original encoded protected header and AAD. -/
def prepareJsonJwe (value : Json) (policy : DecryptionPolicy) :
    Option (List PreparedJwe) := do
  let protectedSegment ← optionalField value "protected" nonemptyText
  let protectedHeader ← protectedSegment.mapM encodedHeader
  let unprotected ← optionalField value "unprotected" nonemptyObj
  let unprotected := unprotected.getD emptyObject
  if (unprotected.getObjVal? "crit").isOk then none else
    let shared ← mergeHeaders (protectedHeader.getD emptyObject) unprotected
    let external ← optionalField value "aad" nonemptyText
    let _ ← external.mapM base64url
    let candidates ← members value "recipients"
    let iv ← optionalField value "iv" nonemptyText
    let ciphertext ← (value.getObjVal? "ciphertext").toOption >>= text
    let tag ← optionalField value "tag" nonemptyText
    candidates.mapM fun recipient => do
      let header ← optionalField recipient "header" readObj
      let header := header.getD emptyObject
      if (header.getObjVal? "crit").isOk then none else
        let merged ← mergeHeaders shared header >>= Header.read true
        let key ← optionalField recipient "encrypted_key" nonemptyText
        let packet ← PreparedJwe.read (jsonAad protectedSegment external) (key.getD "")
          (iv.getD "") ciphertext (tag.getD "")
        if policy.allows merged && packet.hasParameters policy merged then some packet else none

end JosekitSpec
