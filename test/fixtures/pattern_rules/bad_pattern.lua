-- A pattern that is not Lua expression syntax: the loader refuses the file.
return {
   name = "pattern-bad",
   pattern_rules = {
      {id = "broken", pattern = "vendor.run($CMD", severity = "high"},
   },
}
