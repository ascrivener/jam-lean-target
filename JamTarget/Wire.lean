import JAM.Block
import JamTarget.Refine

/-!
# The fuzzer protocol v1 messages (jam-fuzzing `fuzz-proto/fuzz-v1.asn`)

Every message is ℰ (the JAM codec, GP Appendix C) of a `Message` choice: one discriminant octet,
then the variant's encoding. On the wire each message is prefixed by its length as a 32-bit
little-endian integer (framing is in `JamTarget.IO`).

| tag | message      | direction       |
|-----|--------------|-----------------|
| 0   | PeerInfo     | both            |
| 1   | Initialize   | fuzzer → target |
| 2   | StateRoot    | target → fuzzer |
| 3   | ImportBlock  | fuzzer → target |
| 4   | GetState     | fuzzer → target |
| 5   | State        | target → fuzzer |
| 6   | RefineBundle | fuzzer → target |
| 7   | WorkReport   | target → fuzzer |
| 255 | Error        | target → fuzzer |

`Block` and `Header` are GP v0.8.1's, decoded by jam-lean (`JAM.Block.decode`).
-/

namespace JamTarget

open JAM JAM.Decoder

/-- `Version ::= SEQUENCE { major U8, minor U8, patch U8 }`. -/
structure Version where
  major : Nat
  minor : Nat
  patch : Nat
  deriving Repr, BEq

/-- `PeerInfo`. -/
structure PeerInfo where
  fuzzVersion : Nat
  features : Nat
  jamVersion : Version
  appVersion : Version
  appName : String
  deriving Repr

/-- `feature-ancestry` (2^0). -/
def featureAncestry : Nat := 1
/-- `feature-fork` (2^1). -/
def featureFork : Nat := 2
/-- `feature-refine` (2^2, jam-fuzzing PR #214). -/
def featureRefine : Nat := 4

/-- `AncestryItem ::= SEQUENCE { slot TimeSlot, header-hash HeaderHash }`. -/
structure AncestryItem where
  slot : Nat
  hash : List UInt8
  deriving Repr

/-- A raw state: `SEQUENCE OF KeyValue`, with 31-octet keys. -/
abbrev RawState := List (List UInt8 × List UInt8)

/-- The requests the fuzzer sends. -/
inductive Request where
  | peerInfo (p : PeerInfo)
  | initialize (header : Header) (state : RawState) (ancestry : List AncestryItem)
  | importBlock (b : Block)
  | getState (headerHash : List UInt8)
  | refineBundle (q : Refine.Request)

/-- The responses the target sends. -/
inductive Response where
  | peerInfo (p : PeerInfo)
  | stateRoot (root : List UInt8)
  | state (kvs : RawState)
  | workReport (r : WorkReport)
  | error (msg : String)

def version : Decoder Version := do
  return { major := ← fixed 1, minor := ← fixed 1, patch := ← fixed 1 }

def decPeerInfo : Decoder PeerInfo := do
  let fv ← fixed 1
  let f ← fixed 4
  let jv ← version
  let av ← version
  let name ← var
  return { fuzzVersion := fv, features := f, jamVersion := jv, appVersion := av,
           appName := String.fromUTF8? name |>.getD "" }

def rawState : Decoder RawState :=
  varSeq do return ((← bytes 31).toList, (← var).toList)

def ancestryItem : Decoder AncestryItem := do
  return { slot := ← fixed 4, hash := (← bytes 32).toList }

/-- Decode one request (without its length prefix). -/
def Request.decode (p : Params) : Decoder Request := do
  match ← fixed 1 with
  | 0 => return .peerInfo (← decPeerInfo)
  | 1 =>
    let h ← Header.decode p
    let s ← rawState
    let a ← varSeq ancestryItem
    return .initialize h s a
  | 3 => return .importBlock (← Block.decode p)
  | 4 => return .getState (← bytes 32).toList
  | 6 => return .refineBundle (← Refine.Request.decode)
  | t => fail s!"unexpected request tag {t}"

open Codec in
def Version.encode (v : Version) : List UInt8 := fixed 1 v.major ++ fixed 1 v.minor ++ fixed 1 v.patch

open Codec in
def PeerInfo.encode (p : PeerInfo) : List UInt8 :=
  fixed 1 p.fuzzVersion ++ fixed 4 p.features ++ p.jamVersion.encode ++ p.appVersion.encode ++
    Codec.var p.appName.toUTF8

open Codec in
def encodeRawState (kvs : RawState) : List UInt8 :=
  varSeq (fun (k, v) => k ++ nat v.length ++ v) kvs

open Codec in
/-- Encode one response (without its length prefix). -/
def Response.encode : Response → List UInt8
  | .peerInfo p => 0 :: p.encode
  | .stateRoot r => 2 :: r
  | .state kvs => 5 :: encodeRawState kvs
  | .workReport r => 7 :: r.encode
  | .error m => 255 :: Codec.var m.toUTF8

end JamTarget
