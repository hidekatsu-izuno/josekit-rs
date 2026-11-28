import JosekitSpec.Wire

namespace JosekitSpec

open Lean

structure Jwk where
  value : Json
  kid : Option String
  deriving BEq

/-- JWK object shape and the fields that participate in the key-set contract. -/
def Jwk.read (value : Json) : Option Jwk := do
  let _ ← value.getObj?.toOption
  let text := fun v : Json => v.getStr?.toOption
  let _ ← (value.getObjVal? "kty").toOption >>= text
  let kid ← optionalField value "kid" text
  for field in ["use", "alg", "x5u", "crv"] do
    let _ ← optionalField value field text
  let _ ← optionalField value "key_ops" stringList
  let _ ← optionalField value "x5c" certificates
  for field in ["x5t", "x5t#S256", "k", "d", "p", "q", "dp", "dq", "qi", "x", "y"] do
    let _ ← optionalField value field (fun v => text v >>= base64url)
  return ⟨value, kid⟩

abbrev KeySet := List Jwk

namespace KeySet

def read (value : Json) : Option KeySet := do
  let keys ← (value.getObjVal? "keys").toOption
  let keys ← keys.getArr?.toOption
  keys.toList.mapM Jwk.read

def get (keys : KeySet) (kid : String) : List Jwk :=
  keys.filter (fun key => key.kid == some kid)

def push (keys : KeySet) (key : Jwk) : KeySet :=
  keys ++ [key]

def remove (keys : KeySet) (key : Jwk) : KeySet :=
  keys.eraseP (· == key)

theorem mem_get {keys : KeySet} {key : Jwk} {kid : String} :
    key ∈ get keys kid ↔ key ∈ keys ∧ key.kid = some kid := by
  simp [get]

theorem get_push (keys : KeySet) (key : Jwk) (kid : String) :
    get (push keys key) kid = get keys kid ++ (if key.kid = some kid then [key] else []) := by
  by_cases h : key.kid = some kid <;> simp [get, push, h]

theorem get_remove_first (before after : KeySet) (key : Jwk) (kid : String)
    (first : ∀ other ∈ before, (other == key) = false) (self : (key == key) = true) :
    get (remove (before ++ key :: after) key) kid = get before kid ++ get after kid := by
  have h (other : Jwk) (mem : other ∈ before) : ¬ (other == key) = true := by
    simp [first other mem]
  simp [get, remove, List.eraseP_append_right _ h, self]

end KeySet

end JosekitSpec
