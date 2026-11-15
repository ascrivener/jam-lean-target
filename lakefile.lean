import Lake
open Lake DSL

/-! jam-lean-target: the jam-lean model (Gray Paper v0.8.0) as a target of the JAM conformance
    fuzzer (jam-conformance/jam-fuzzing, fuzzer protocol v1).

* `lake build`             builds the target executable `jam-lean-target`.
* `lake exe jam-lean-target serve`            speaks the protocol on stdin/stdout.
* `lake exe jam-lean-target session DIR`      replays a recorded fuzzer session (minifuzz format).
* `lake exe jam-lean-target trace DIR …`      imports block-import traces and compares post-states.

Only the `PVM` and `JAM` libraries of jam-lean are used, never `Services`. -/

package «jam-lean-target» where
  leanOptions := #[⟨`autoImplicit, false⟩]

require «jam-lean» from git "https://github.com/ascrivener/jam-lean" @ "bda9d741fd6e3db69aa6f6f52f6574a38d084538"

lean_lib JamTarget

@[default_target]
lean_exe «jam-lean-target» where
  root := `Main
