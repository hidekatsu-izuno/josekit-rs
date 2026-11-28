import JosekitSpec.JwkIndex
import JosekitSpec.CompactFlow

namespace JosekitSpec

open JwkIndex (State)

-- Operations on the projection of Rust's Vec, BTreeMap and Arc.
def appendToBucket (state : State) (entry : JwkIndex.Entry) : State :=
  { state with buckets := fun kid =>
    if entry.key.kid = some kid then state.buckets kid ++ [entry] else state.buckets kid }

def appendToEntries (state : State) (entry : JwkIndex.Entry) : State :=
  { state with entries := state.entries ++ [entry] }

def eraseEntry (state : State) (index : Nat) : State :=
  { state with entries := state.entries.eraseIdx index }

def retainOtherEntries (state : State) (removed : Option JwkIndex.Entry) : State :=
  match removed with
  | none => state
  | some removed =>
    { state with buckets := fun kid =>
      if removed.key.kid == some kid then
        (state.buckets kid).filter (fun entry => entry.id != removed.id)
      else state.buckets kid }

/-- A Result which retains the callback arguments even if a subsequent call returns Err. -/
structure Trace (Event : Type) (α : Type) where
  calls : List Event
  result : Option α

def Trace.pure (result : α) : Trace Event α := ⟨[], some result⟩

def Trace.bind (action : Trace Event α) (next : α → Trace Event β) : Trace Event β :=
  match action.result with
  | none => ⟨action.calls, none⟩
  | some value =>
    let remainder := next value
    ⟨action.calls ++ remainder.calls, remainder.result⟩

instance : Monad (Trace Event) where
  pure := Trace.pure
  bind := Trace.bind

def liftOption (result : Option α) : Trace Event α := ⟨[], result⟩

def event (call : Event) (result : Option α) : Trace Event α := ⟨[call], result⟩

def Trace.outcome (trace : Trace Event ByteArray) : CompactFlow.Outcome Event :=
  ⟨trace.calls, trace.result⟩

end JosekitSpec
