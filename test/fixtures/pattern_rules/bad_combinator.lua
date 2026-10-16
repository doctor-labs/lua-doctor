-- A pattern_not that is not Lua expression syntax: the loader refuses the file.
return {
   name = "pattern-bad-combinator",
   pattern_rules = {
      {id = "broken-not", pattern = "vendor.run($CMD)", pattern_not = "vendor.run($CMD", severity = "high"},
   },
}
