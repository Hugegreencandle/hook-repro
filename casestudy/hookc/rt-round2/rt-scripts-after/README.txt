RT round 2 repro scripts (n*.sh/py, from the red-team's scratchpad rt2/) and their outputs.
  <name>.out        = output on ec8eaeb (the red-team's run, before the fixes)
  <name>.after.out  = output on the fixed code (fix/rt-round1 @0232399), run by run_rt2_after.sh
  n1c_*, n5b_*, n6b_* = fix checks added in round 2 (the original n1 premise can no longer be produced by
                     hookc build, so n1c reconstructs ec8eaeb's sidecar; n5b uses a macro-computed operand the
                     pre-scan cannot see; n6 looks for other field names, n6b prints builder.platforms_built).
  r1/               = the round-1 scripts re-run on the same fixed code (run_all.rt2.log).
Paths are shortened (<scratchpad>, ~). Script exit codes are the scripts' own (several end with a
python one-liner that reads a sidecar a refused build never wrote); the verdict lines carry the result.
