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

describe("951 with selene's semantics (#357)", function()
   local ALLOW = {category = {"lint"}, allow_defined = true}

   it("a global the file assigns is defined where it is read", function()
      local source = "print(helper)\nfunction helper() end\nhelper()\n"
      assert_equal(#names_of(source, ALLOW), 0)
      assert_equal(#names_of(source), 2, "luacheck's default still reports both reads")
   end)

   it("hoisting reaches a global assigned later, as in selene's hoisting test", function()
      assert_equal(#names_of("function f() x() print(y) end\nfunction x() end\ny = 3\n", ALLOW), 0)
   end)

   it("a global that is never assigned is still undefined", function()
      assert_equal(#names_of("print(helper)\nfunction other() end\n", ALLOW), 1)
   end)

   it("a local defined later is not a global definition", function()
      assert_equal(#names_of("function f() z() end\nlocal function z() end\n", ALLOW), 1)
   end)

   it("the defining set is not reported as a non-standard global", function()
      assert_equal(#names_of("function helper() end\n", ALLOW, "952"), 0)
   end)

   it("a field of an assigned global is not reported either", function()
      assert_equal(#names_of("cfg = {}\ncfg.debug = 1\nprint(cfg.debug)\n", ALLOW, "951"), 0)
   end)

   it("--allow-defined is the same option on the command line", function()
      local dir = harness.scratch_dir("lint_allow")
      local path = dir .. "/t.lua"
      local handle = assert(io.open(path, "w"))
      handle:write("print(helper)\nfunction helper() end\n")
      handle:close()
      local plain = harness.cli({"--category", "lint", path})
      assert_match(plain, "%[951%]", plain)
      local allowed, code = harness.cli({"--category", "lint", "--allow-defined", path})
      assert_equal(code, 0, allowed)
   end)

   it("names the built-in standard that defines a name, as selene does", function()
      local found
      for _, finding in ipairs(api.check_source("local a = translate('x')\n", LINT)) do
         if finding.code == "951" then found = finding end
      end
      assert_true(found, "expected a 951")
      assert_match(found.message, "defined by %-%-std %+luci", found.message)
   end)

   it("the luci standard defines the dispatcher functions a controller calls", function()
      assert_equal(#names_of("entry({'a'}, call('b'), _('c'))\n", {category = {"lint"}, std = "+luci"}), 0)
   end)
end)

describe("957 more arguments than the function takes (#381)", function()
   local function hits(source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == "957" then out[#out + 1] = finding end
      end
      return out
   end

   it("a standard function given an extra argument is reported", function()
      local found = hits("local n = os.getenv('HOME', 'extra')\n")
      assert_equal(#found, 1)
      assert_equal(found[1].name, "os.getenv")
      assert_match(found[1].message, "takes 1, 2 passed", found[1].message)
   end)

   it("a sink with a misplaced argument is reported", function()
      assert_equal(#hits("os.execute('ls', 'extra')\n"), 1)
   end)

   it("the widest signature across Lua versions is accepted", function()
      assert_equal(#hits("load('x', 'name', 't', {})\nlocal s = ('x'):rep(3)\nstring.rep('x', 3, ',')\n"), 0)
   end)

   it("a vararg function accepts any number", function()
      assert_equal(#hits("print(1, 2, 3, 4, 5)\nstring.format('%d %d', 1, 2)\n"), 0)
   end)

   it("a local function is checked against its parameters", function()
      assert_equal(#hits("local function add(a, b) return a + b end\nadd(1, 2, 3)\n"), 1)
      assert_equal(#hits("local function add(a, b) return a + b end\nadd(1, 2)\nadd(1)\n"), 0)
   end)

   it("a local function that takes ... is never reported", function()
      assert_equal(#hits("local function f(a, ...) end\nf(1, 2, 3, 4)\n"), 0)
   end)

   it("a redefined local function uses the most generous definition", function()
      assert_equal(#hits("local f = function(a) end\nf = function(a, b, c) end\nf(1, 2, 3)\n"), 0)
   end)

   it("a shadowing local is not the library function", function()
      assert_equal(#hits("local os = {getenv = function(a, b) end}\nos.getenv(1, 2)\n"), 0)
   end)

   it("a profile's params make its own API checkable", function()
      local rules = harness.scratch_dir("lint_params") .. "/profile.lua"
      local handle = assert(io.open(rules, "w"))
      handle:write('return {name = "mine", sinks = {{pattern = "vendor.run", code = "701", kind = "exec",'
         .. ' arg = {1}, params = {"string", "number?"}}}}\n')
      handle:close()
      assert_equal(#hits("vendor.run('a', 1, 2)\n", {category = {"lint"}, rules = {rules}}), 1)
      assert_equal(#hits("vendor.run('a', 1)\n", {category = {"lint"}, rules = {rules}}), 0)
   end)

   it("a malformed params list is refused", function()
      local rules = harness.scratch_dir("lint_params_bad") .. "/profile.lua"
      local handle = assert(io.open(rules, "w"))
      handle:write('return {name = "mine", sinks = {{pattern = "vendor.run", code = "701", kind = "exec",'
         .. ' arg = {1}, params = {"..."  , "string"}}}}\n')
      handle:close()
      local out, code = harness.cli({"--rules", rules, "--category", "lint", "test/fixtures/clean"})
      assert_equal(code, 2, out)
   end)

   it("is off unless asked for", function()
      assert_equal(#hits("os.getenv('a', 'b')\n", {}), 0)
   end)
end)

describe("958 standard library misuse (#382)", function()
   local function problems(source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == "958" then out[#out + 1] = finding.message end
      end
      return out
   end

   it("a missing required argument is reported", function()
      local found = problems('local line = string.rep("-")\n')
      assert_equal(#found, 1)
      assert_match(found[1], "too few arguments to string.rep: it requires 2, 1 passed", found[1])
   end)

   it("a trailing call or ... may supply the rest", function()
      assert_equal(#problems('local a = string.rep(f())\nlocal b = string.sub(...)\n'), 0)
   end)

   it("an optional argument may be left out or skipped with nil", function()
      assert_equal(#problems('local a = string.find("x", "y")\nlocal b = string.find("x", "y", nil)\n'), 0)
   end)

   it("a literal of the wrong type is reported", function()
      local found = problems("local a = os.getenv({})\n")
      assert_equal(#found, 1)
      assert_match(found[1], "argument 1 of os.getenv should be a string, a table was passed", found[1])
   end)

   it("a string that is not a number fails a number parameter, a numeric one does not", function()
      assert_equal(#problems('local a = math.floor("abc")\n'), 1)
      assert_equal(#problems('local a = math.floor("3.5")\nlocal b = string.rep("x", "3")\n'), 0)
   end)

   it("a number passes a string parameter", function()
      assert_equal(#problems("local a = string.len(123)\n"), 0)
   end)

   it("a nil literal for a required parameter is reported", function()
      assert_equal(#problems("local a = string.upper(nil)\n"), 1)
   end)

   it("a pure function called as a statement is reported", function()
      local found = problems("string.upper(s)\n")
      assert_equal(#found, 1)
      assert_match(found[1], "the result of string.upper is not used", found[1])
   end)

   it("a pure function whose result is used is not", function()
      assert_equal(#problems("local s = string.upper(s)\nprint(string.upper(s))\n"), 0)
   end)

   it("a function called for its effect is not", function()
      assert_equal(#problems("os.execute('ls')\ntable.insert(t, 1)\nprint('x')\n"), 0)
   end)

   it("a shadowed library name is not the standard library", function()
      assert_equal(#problems('local string = {rep = function() end}\nstring.rep("x")\n'), 0)
   end)

   it("is off unless asked for", function()
      assert_equal(#problems('local line = string.rep("-")\n', {}), 0)
   end)
end)

describe("959-962 selene correctness lints (#367, #368, #369, #370)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("959 a key written twice in one table constructor", function()
      local hits = found("959", 'local t = {a = 1, b = 2, a = 3}\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], "duplicate key a", hits[1])
      assert_equal(#found("959", 'local t = {["a"] = 1, a = 2}\n'), 1)
      assert_equal(#found("959", 'local t = {[1] = "x", [1] = "y"}\n'), 1)
      assert_equal(#found("959", 'local t = {a = 1, b = 2, [k] = 3, [k] = 4}\n'), 0)
   end)

   it("960 comparing with NaN", function()
      local hits = found("960", 'if x == 0/0 then end\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], "x ~= x", hits[1])
      assert_equal(#found("960", 'if 0/0 ~= y then end\n'), 1)
      assert_equal(#found("960", 'if x == 0 then end\nif x ~= x then end\n'), 0)
   end)

   it("961 comparing with a table constructor", function()
      assert_equal(#found("961", 'if x == {} then end\n'), 1)
      assert_equal(#found("961", 'if {1} ~= y then end\n'), 1)
      assert_equal(#found("961", 'if x == y then end\nlocal t = {}\n'), 0)
   end)

   it("962 an assignment pair that looks like a broken swap", function()
      local hits = found("962", 'a = b\nb = a\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], "a, b = b, a", hits[1])
      assert_equal(#found("962", 'a = b\nc = a\n'), 0)
      assert_equal(#found("962", 'a, b = b, a\n'), 0)
   end)

   it("all four stay off by default", function()
      for _, code in ipairs({"959", "960", "961", "962"}) do
         assert_equal(#found(code, 'local t = {a = 1, a = 2}\nif x == 0/0 or x == {} then end\na = b\nb = a\n', {}), 0)
      end
   end)
end)
