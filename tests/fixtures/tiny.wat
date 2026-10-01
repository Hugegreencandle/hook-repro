(module
 (import "env" "accept" (func $accept (param i32 i32 i64) (result i64)))
 (func (export "hook") (param i32) (result i64)
  i32.const 0 i32.const 0 i64.const 0 call $accept))
