-- A declaration with pattern rules, loaded with --rules. `$NAME` is a metavariable:
-- it matches any one expression, and a name used twice must match the same one.
return {
   name = "pattern-fixture",
   pattern_rules = {
      {id = "vendor-run", pattern = "vendor.run($CMD)", severity = "high", confidence = "high", cwe = "CWE-78"},
      {id = "same-twice", pattern = "same($A, $A)", severity = "medium", confidence = "high"},
   },
}
