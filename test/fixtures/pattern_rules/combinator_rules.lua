-- Combinators on declared pattern rules: pattern_either, pattern_not and pattern_inside.
return {
   name = "pattern-combinators",
   pattern_rules = {
      {id = "either-run", pattern_either = {"vendor.run($CMD)", "vendor.exec($CMD)"}, severity = "high", confidence = "high", cwe = "CWE-78"},
      {id = "run-not-ls", pattern = "vendor.run($CMD)", pattern_not = "vendor.run(\"ls\")", severity = "medium", confidence = "high"},
      {id = "run-in-wrap", pattern = "vendor.run($CMD)", pattern_inside = "wrap($BODY)", severity = "medium", confidence = "high"},
   },
}
