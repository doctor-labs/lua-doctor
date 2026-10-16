local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

local RULES = "test/fixtures/pattern_rules/combinator_rules.lua"
local BAD = "test/fixtures/pattern_rules/bad_combinator.lua"

local function named(report, name)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == "742" and finding.name == name then out[#out + 1] = finding end
   end
   return out
end

describe("pattern rules combinators", function()
   it("pattern_either fires on any listed alternative, once per expression", function()
      local hits = named(api.check_source([[
vendor.run(x)
vendor.exec(y)
vendor.other(z)
]], {rules = {RULES}}), "either-run")
      assert_equal(#hits, 2)
      assert_equal(hits[1].line, 1)
      assert_equal(hits[2].line, 2)
   end)

   it("pattern_not drops the matches it excludes", function()
      local hits = named(api.check_source([[
vendor.run("ls")
vendor.run(cgi.x)
]], {rules = {RULES}}), "run-not-ls")
      assert_equal(#hits, 1)
      assert_equal(hits[1].line, 2)
   end)

   it("pattern_inside only fires for expressions within the enclosing pattern", function()
      local hits = named(api.check_source([[
wrap(vendor.run(x))
vendor.run(y)
]], {rules = {RULES}}), "run-in-wrap")
      assert_equal(#hits, 1)
      assert_equal(hits[1].line, 1)
   end)

   it("refuses a rule whose pattern_not is not Lua expression syntax", function()
      local ok, message = api.rules_load({BAD})
      assert_true(ok == nil, "malformed pattern_not is refused")
      assert_true(message:find("broken-not", 1, true) ~= nil, "message names the rule: " .. tostring(message))
   end)
end)
