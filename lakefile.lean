import Lake
open Lake DSL

/-! jam-lean-target: the jam-lean model (Gray Paper v0.8.1) as a target of the JAM conformance
    fuzzer (jam-conformance/jam-fuzzing, fuzzer protocol v1).

* `lake build`             builds the target executable `jam-lean-target`.
* `lake exe jam-lean-target serve`            speaks the protocol on stdin/stdout.
* `lake exe jam-lean-target session DIR`      replays a recorded fuzzer session (minifuzz format).
* `lake exe jam-lean-target trace DIR …`      imports block-import traces and compares post-states.

Only the `PVM`, `JAM` and `JamCrypto` libraries of jam-lean are used, never `Services`. -/

package «jam-lean-target» where
  leanOptions := #[⟨`autoImplicit, false⟩]

require «jam-lean» from git "https://github.com/ascrivener/jam-lean" @ "f952c50918f7cee1d823a8fbbe42879b926fd80f"

lean_lib JamTarget

@[default_target]
lean_exe «jam-lean-target» where
  root := `Main

/-- The Lean side of the PVM differential harness (jam-lean's Ψ on jamtestvectors-format cases):
    `lake exe pvmrun check vectors/pvm`, `lake exe pvmrun run FILE|DIR…`. -/
lean_exe pvmrun where
  root := `PvmRun

/-- Refine vectors: `lake exe refinegen BASE-INITIALIZE.bin OUT` writes fuzzer sessions with
    `RefineBundle` (see vectors/refine). -/
lean_exe refinegen where
  root := `RefineGen
