return {
   name = "hyphen-combinators",
   pattern_rules = {
      {
         id = "hyphen-test",
         ["pattern-either"] = {"vendor.run($X)", "vendor.exec($X)"},
         ["pattern-inside"] = "wrap($Y)",
         ["pattern-not"] = "vendor.run(\"ls\")",
         severity = "high",
         confidence = "high",
         cwe = "CWE-78",
      },
   },
}
