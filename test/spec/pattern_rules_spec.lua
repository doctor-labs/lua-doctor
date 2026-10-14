local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

local RULES = "test/fixtures/pattern_rules/vendor_rules.lua"
local BAD = "test/fixtures/pattern_rules/bad_pattern.lua"

local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

describe("pattern rules", function()
   it("reports each call a declared pattern matches, and names the rule", function()
      local report = api.check_source([[
vendor.run("ls")
vendor.run(cgi.x)
vendor.other("ls")
]], {rules = {RULES}})
      local hits = with_code(report, "742")
      assert_equal(#hits, 2)
      assert_equal(hits[1].name, "vendor-run")
      assert_equal(hits[1].line, 1)
      assert_equal(hits[2].line, 2)
      assert_equal(hits[1].severity, "high")
      assert_equal(hits[1].cwe, "CWE-78")
   end)

   it("matches a repeated metavariable only when both occurrences are the same expression", function()
      local same = with_code(api.check_source([[
same(x, x)
]], {rules = {RULES}}), "742")
      local different = with_code(api.check_source([[
same(x, y)
]], {rules = {RULES}}), "742")
      assert_equal(#same, 1)
      assert_equal(same[1].name, "same-twice")
      assert_equal(#different, 0)
   end)

   it("refuses a rule file whose pattern is not Lua expression syntax", function()
      local ok, message = api.rules_load({BAD})
      assert_true(ok == nil, "malformed pattern is refused")
      assert_true(message:find("broken", 1, true) ~= nil, "message names the rule: " .. tostring(message))
   end)
end)
