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

describe("952 setting or mutating a non-standard global (#335)", function()
   it("reports assigning a global the std does not define as setting", function()
      local found
      for _, finding in ipairs(api.check_source("counter = 0\n", LINT)) do
         if finding.code == "952" then found = finding end
      end
      assert_true(found, "expected a 952")
      assert_match(found.message, "^setting non%-standard global variable %(counter%)", found.message)
   end)

   it("reports writing a field of one as mutating", function()
      local found
      for _, finding in ipairs(api.check_source("config.debug = true\n", LINT)) do
         if finding.code == "952" then found = finding end
      end
      assert_true(found, "expected a 952")
      assert_match(found.message, "^mutating", found.message)
   end)

   it("a function declared as a global is a set", function()
      assert_equal(#names_of("function helper() end\n", nil, "952"), 1)
   end)

   it("a local is not reported", function()
      assert_equal(#names_of("local counter = 0\ncounter = counter + 1\n", nil, "952"), 0)
   end)

   it("a global a platform profile declares is not reported", function()
      assert_equal(#names_of("luci.foo = 1\n", {category = {"lint"}, std = "+luci"}, "952"), 0)
   end)

   it("is off unless asked for", function()
      assert_equal(#names_of("counter = 0\n", {}, "952"), 0)
   end)
end)

describe("953 setting a read-only global (#336)", function()
   local function messages(source)
      local out = {}
      for _, finding in ipairs(api.check_source(source, LINT)) do
         if finding.code == "953" then out[#out + 1] = finding.message end
      end
      return out
   end

   it("reports assigning a standard global as setting", function()
      local found = messages("print = nil\n")
      assert_equal(#found, 1)
      assert_match(found[1], "^setting read%-only global variable %(print%)", found[1])
   end)

   it("reports assigning a field of a standard library as setting a field", function()
      local found = messages("os.execute = function() end\n")
      assert_equal(#found, 1)
      assert_match(found[1], "^setting a field of read%-only global variable %(os%)", found[1])
   end)

   it("is not also a 952", function()
      assert_equal(#names_of("string.format = f\n", nil, "952"), 0)
   end)

   it("_G is writable, so setting a field of it is not reported", function()
      assert_equal(#messages("_G.anything = 1\n"), 0)
   end)

   it("a local with a standard name is not reported", function()
      assert_equal(#messages("local print = print\nprint = nil\n"), 0)
   end)

   it("is off unless asked for", function()
      assert_equal(#names_of("print = nil\n", {}, "953"), 0)
   end)
end)

describe("954 undefined field of a global (#338)", function()
   local function found(source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == "954" then out[#out + 1] = finding end
      end
      return out
   end

   it("reports reading a field the library does not have, naming the path", function()
      local hits = found('local t = string.fromat("%d", 3)\n')
      assert_equal(#hits, 1)
      assert_equal(hits[1].name, "string.fromat")
      assert_match(hits[1].message, "^accessing undefined field of global", hits[1].message)
   end)

   it("reports writing one as setting", function()
      local hits = found("table.mapp = print\n")
      assert_equal(#hits, 1)
      assert_match(hits[1].message, "^setting undefined field", hits[1].message)
   end)

   it("a real field is not reported", function()
      assert_equal(#found("local t = string.format('%d', 3)\nprint(os.time())\n"), 0)
   end)

   it("a nested path is named in full", function()
      assert_equal(found("local n = math.huge.nope\n")[1].name, "math.huge.nope")
   end)

   it("the Lua standard decides which fields exist", function()
      assert_equal(#found("local x = table.maxn(t)\n", {category = {"lint"}, std = "lua54"}), 1)
      assert_equal(#found("local x = table.maxn(t)\n", {category = {"lint"}, std = "lua51"}), 0)
   end)

   it("a platform table accepts any field", function()
      assert_equal(#found("local x = luci.sys.whatever\n", {category = {"lint"}, std = "+luci"}), 0)
   end)

   it("is off unless asked for", function()
      assert_equal(#found("local t = string.fromat(1)\n", {}), 0)
   end)
end)
