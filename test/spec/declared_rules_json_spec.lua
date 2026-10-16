-- --rules accepts a JSON declaration: a vendor's sources and sinks as data,
-- read without running any Lua, in the same shape a Lua profile returns.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luadoctor.api"
local json = require "luadoctor.util.json"
local profiles = require "luadoctor.registry.profiles"

local RULES = "test/fixtures/declared_rules/acme.json"

local function count(report, code)
   local n = 0
   for _, finding in ipairs(report) do if finding.code == code then n = n + 1 end end
   return n
end

describe("--rules JSON declaration", function()
   it("loads a declaration with sources and sinks as data", function()
      local declaration, err = profiles.load_file(RULES)
      assert_true(declaration ~= nil, tostring(err))
      assert_equal(declaration.name, "acme")
      assert_equal(declaration.sinks[1].pattern, "acme.run")
      assert_equal(declaration.sinks[1].arg[1], 1)
   end)

   it("a declared sink fed by request data is reported", function()
      local report = api.check_source('acme.run(cgi["cmd"])\n', {std = "cgilua", rules = {RULES}})
      assert_equal(count(report, "709"), 1, "declared sink not reported")
   end)

   it("a call to an undeclared function is not reported", function()
      local report = api.check_source('acme.log(cgi["cmd"])\n', {std = "cgilua", rules = {RULES}})
      assert_equal(count(report, "709"), 0)
   end)

   it("the CLI reports a declared sink from a JSON --rules file", function()
      local out, code = harness.cli({"--std", "cgilua", "--rules", RULES,
         "test/fixtures/declared_rules/handler.lua"})
      assert_equal(code, 1, out)
      assert_match(out, "[709]", out)
   end)

   it("a malformed JSON declaration is rejected with a message, not silently ignored", function()
      local declaration, err = profiles.load_file("test/fixtures/declared_rules/broken.json")
      assert_true(declaration == nil, "a broken JSON --rules file must not load")
      assert_match(tostring(err), "broken.json")
   end)

   it("refuses JSON nested past the depth cap instead of recursing without bound", function()
      local dir = harness.scratch_dir("spec_rules_deep")
      local f = assert(io.open(dir .. "/deep.json", "w"))
      f:write(string.rep("[", 10000))
      f:close()
      local out, code = harness.cli({"--rules", dir .. "/deep.json",
         "test/fixtures/declared_rules/handler.lua"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 2, out)
      assert_match(out, "nested deeper than 64", out)
   end)

   it("refuses JSON input over 1 MiB with a message", function()
      local value, err = json.decode(string.rep(" ", 1024 * 1024 + 1))
      assert_true(value == nil, "oversize input must not decode")
      assert_match(tostring(err), "larger than", tostring(err))
   end)

   it("still decodes nesting at the depth cap", function()
      local value = json.decode(string.rep("[", 64) .. string.rep("]", 64))
      assert_true(value ~= nil, "nesting of exactly 64 is allowed")
   end)
end)
