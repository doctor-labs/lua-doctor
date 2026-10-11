-- The opt-in lint family (950-979), starting with 951 (#334): accessing an
-- undefined variable, judged by luacheck's standard tables.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_equal, assert_match = harness.assert_true, harness.assert_equal, harness.assert_match

local api = require "luadoctor.api"

local LINT = {category = {"lint"}}

local function names_of(source, opts, code)
   local out = {}
   for _, finding in ipairs(api.check_source(source, opts or LINT)) do
      if finding.code == (code or "951") then out[#out + 1] = finding.name end
   end
   return out
end

describe("951 accessing an undefined variable (#334)", function()
   it("reports a misspelled global", function()
      assert_equal(table.concat(names_of('pritn("x")\n'), ","), "pritn")
   end)

   it("does not report a standard global or a standard field", function()
      assert_equal(#names_of('print(os.time(), string.format("x"))\n'), 0)
   end)

   it("does not report a local, a parameter or an upvalue", function()
      assert_equal(#names_of("local a = 1\nlocal function f(b) return a + b end\nf(1)\n"), 0)
   end)

   it("a global the file assigns is still undefined where it is read", function()
      assert_equal(table.concat(names_of("function helper() end\nhelper()\n"), ","), "helper")
   end)

   it("reports each access", function()
      assert_equal(#names_of("print(foo)\nprint(foo)\n"), 2)
   end)

   it("a platform profile defines the roots of its patterns", function()
      local opts = {category = {"lint"}, std = "+luci"}
      assert_equal(#names_of("local x = luci.http.formvalue('a')\n", opts), 0)
      assert_equal(#names_of("print(nosuchthing)\n", opts), 1)
   end)

   it("a profile's own globals are defined", function()
      local rules = harness.scratch_dir("lint_globals") .. "/profile.lua"
      local handle = assert(io.open(rules, "w"))
      handle:write('return {name = "mine", globals = {read_globals = {"translate"}}}\n')
      handle:close()
      assert_equal(#names_of("print(translate('x'))\n", {category = {"lint"}, rules = {rules}}), 0)
      assert_equal(#names_of("print(translatee('x'))\n", {category = {"lint"}, rules = {rules}}), 1)
   end)

   it("the Lua standard decides: setfenv is 5.1, not 5.4", function()
      assert_equal(#names_of("setfenv(1, {})\n", {category = {"lint"}, std = "lua54"}), 1)
      assert_equal(#names_of("setfenv(1, {})\n", {category = {"lint"}, std = "lua51"}), 0)
   end)

   it("is off unless asked for", function()
      assert_equal(#names_of("pritn('x')\n", {}), 0)
      assert_equal(#names_of("pritn('x')\n", {enable = {"95"}}), 1)
      assert_equal(#names_of("pritn('x')\n", {only = {"951"}}), 1)
   end)

   it("a default CLI run neither reports it nor changes the score", function()
      local dir = harness.scratch_dir("lint_cli")
      local path = dir .. "/t.lua"
      local handle = assert(io.open(path, "w"))
      handle:write("pritn('x')\n")
      handle:close()
      local out, code = harness.cli({path})
      assert_equal(code, 0, out)
      assert_true(not out:find("951", 1, true), out)
      local lint_out, lint_code = harness.cli({"--category", "lint", path})
      assert_equal(lint_code, 1, lint_out)
      assert_match(lint_out, "%[951%]", lint_out)
      assert_match(lint_out, "lint 1", lint_out)
   end)
end)
