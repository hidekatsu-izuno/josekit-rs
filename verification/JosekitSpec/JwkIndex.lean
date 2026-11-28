import JosekitSpec.Jwk

namespace JosekitSpec.JwkIndex

/-- An identity represents a distinct allocation, even when two keys compare equal. -/
structure Entry where
  id : Nat
  key : Jwk

def matchesKid (kid : String) (entry : Entry) : Bool :=
  entry.key.kid == some kid

private def matchesKey (key : Jwk) (entry : Entry) : Bool :=
  entry.key == key

/-- Empty buckets represent both an absent index entry and an empty vector. -/
structure State where
  entries : List Entry
  buckets : String → List Entry

def State.keys (state : State) : KeySet :=
  state.entries.map Entry.key

def State.get (state : State) (kid : String) : List Jwk :=
  (state.buckets kid).map Entry.key

def State.empty : State := ⟨[], fun _ => []⟩

def State.push (state : State) (entry : Entry) : State :=
  ⟨state.entries ++ [entry], fun kid =>
    state.buckets kid ++ (if matchesKid kid entry then [entry] else [])⟩

def State.remove (state : State) (key : Jwk) : State :=
  match state.entries.find? (matchesKey key) with
  | none => state
  | some removed =>
    ⟨state.entries.eraseP (matchesKey key), fun kid =>
      if matchesKid kid removed then
        (state.buckets kid).filter (fun entry => entry.id != removed.id)
      else state.buckets kid⟩

def State.Fresh (state : State) (entry : Entry) : Prop :=
  ∀ other ∈ state.entries, other.id ≠ entry.id

def State.Valid (state : State) : Prop :=
  state.entries.Pairwise (fun a b => a.id ≠ b.id) ∧
    ∀ kid, state.buckets kid = state.entries.filter (matchesKid kid)

theorem State.empty_valid : State.empty.Valid := by
  simp [empty, Valid]

theorem State.push_valid {state : State} {entry : Entry} (h : state.Valid) (fresh : state.Fresh entry) :
    (state.push entry).Valid := by
  refine ⟨?_, ?_⟩
  · simpa [push, List.pairwise_append] using And.intro h.1 fresh
  · intro kid
    by_cases hm : matchesKid kid entry <;> simp [push, h.2, hm]

private theorem retain_other_ids {entries : List Entry} {removed : Entry} {kid : String}
    (h : ∀ entry ∈ entries, entry.id ≠ removed.id) :
    (entries.filter (matchesKid kid)).filter (fun entry => entry.id != removed.id) =
      entries.filter (matchesKid kid) := by
  apply List.filter_eq_self.mpr
  intro entry hm
  exact bne_iff_ne.mpr (h entry (List.mem_filter.mp hm).1)

theorem State.remove_valid {state : State} (h : state.Valid) (key : Jwk) : (state.remove key).Valid := by
  unfold remove
  split
  · exact h
  · rename_i removed found
    obtain ⟨hit, before, after, entries, first⟩ := List.find?_eq_some_iff_append.mp found
    have erased : state.entries.eraseP (matchesKey key) = before ++ after := by
      rw [entries, List.eraseP_append_right _]
      · simp [hit]
      · intro entry hm
        simpa using first entry hm
    refine ⟨List.Pairwise.sublist List.eraseP_sublist h.1, ?_⟩
    intro kid
    have hp := h.1
    rw [entries, List.pairwise_append, List.pairwise_cons] at hp
    have left (entry : Entry) (hm : entry ∈ before) : entry.id ≠ removed.id :=
      hp.2.2 entry hm removed (by simp)
    have right (entry : Entry) (hm : entry ∈ after) : entry.id ≠ removed.id :=
      Ne.symm (hp.2.1.1 entry hm)
    change (if matchesKid kid removed then
      (state.buckets kid).filter (fun entry => entry.id != removed.id) else state.buckets kid) =
        (state.entries.eraseP (matchesKey key)).filter (matchesKid kid)
    rw [h.2 kid, erased, entries]
    simp only [List.filter_append]
    by_cases matched : matchesKid kid removed
    · simp [List.filter_cons, matched, retain_other_ids (kid := kid) left,
        retain_other_ids (kid := kid) right]
    · simp [List.filter_cons, matched]

theorem State.get_refines {state : State} (h : state.Valid) (kid : String) :
    state.get kid = state.keys.get kid := by
  rw [get, h.2 kid, keys, KeySet.get, List.filter_map]
  rfl

theorem State.push_refines (state : State) (entry : Entry) :
    (state.push entry).keys = state.keys.push entry.key := by
  simp [push, keys, KeySet.push]

theorem State.remove_refines (state : State) (key : Jwk) :
    (state.remove key).keys = state.keys.remove key := by
  unfold remove
  simp only [keys, KeySet.remove, List.eraseP_map, Function.comp_def]
  split
  · rename_i h
    have miss := List.find?_eq_none.mp h
    change state.entries.map Entry.key = (state.entries.eraseP (matchesKey key)).map Entry.key
    rw [List.eraseP_eq_self_iff.mpr miss]
  · rfl

/-- Allocation is fresh for each inserted key, as with an independent live Arc. -/
inductive Reachable : State → Prop where
  | empty : Reachable State.empty
  | push {state : State} (reachable : Reachable state) (entry : Entry)
      (fresh : state.Fresh entry) : Reachable (state.push entry)
  | remove {state : State} (reachable : Reachable state) (key : Jwk) :
      Reachable (state.remove key)

theorem Reachable.valid {state} (h : Reachable state) : state.Valid := by
  induction h with
  | empty => exact State.empty_valid
  | push _ _ fresh ih => exact State.push_valid ih fresh
  | remove _ key ih => exact State.remove_valid ih key

theorem Reachable.get_refines {state} (h : Reachable state) (kid : String) :
    state.get kid = state.keys.get kid :=
  State.get_refines h.valid kid

end JosekitSpec.JwkIndex
