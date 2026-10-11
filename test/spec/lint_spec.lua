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

describe("963-965 empty branches, empty loops, reversed numeric for (#349, #361, #362, #351, #363)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("963 an if branch with nothing in it", function()
      assert_equal(#found("963", 'if x then end\n'), 1)
      assert_equal(#found("963", 'if x then f() else end\n'), 1)
      assert_equal(#found("963", 'if x then f() elseif y then else g() end\n'), 1)
      assert_equal(#found("963", 'if x then f() else g() end\n'), 0)
      assert_equal(#found("963", 'if x then -- a comment only\nend\n'), 1)
   end)

   it("964 a loop with an empty body", function()
      assert_equal(#found("964", 'for i = 1, 10 do end\n'), 1)
      assert_equal(#found("964", 'for k, v in pairs(t) do end\n'), 1)
      assert_equal(#found("964", 'while x do end\n'), 1)
      assert_equal(#found("964", 'repeat until x\n'), 1)
      assert_equal(#found("964", 'for i = 1, 10 do f(i) end\n'), 0)
   end)

   it("965 a numeric for that counts down without a negative step", function()
      local hits = found("965", 'for i = #t, 1 do f(i) end\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], ", -1", hits[1])
      assert_equal(#found("965", 'for i = 10, 1 do f(i) end\n'), 1)
      assert_equal(#found("965", 'for i = 10, 1, -1 do f(i) end\n'), 0)
      assert_equal(#found("965", 'for i = 1, 10 do f(i) end\n'), 0)
      assert_equal(#found("965", 'for i = n, m do f(i) end\n'), 0)
   end)

   it("all three stay off by default", function()
      for _, code in ipairs({"963", "964", "965"}) do
         assert_equal(#found(code, 'if x then end\nwhile x do end\nfor i = 10, 1 do f(i) end\n', {}), 0)
      end
   end)
end)

describe("966-968 selene if_same_then_else, ifs_same_cond, mixed_table (#365, #366, #371)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("966 an if whose branches do the same thing", function()
      assert_equal(#found("966", 'if x then f(1) else f(1) end\n'), 1)
      assert_equal(#found("966", 'if x then f(1) elseif y then f(1) end\n'), 1)
      assert_equal(#found("966", 'if x then f(1) else f(2) end\n'), 0)
      assert_equal(#found("966", 'if x then else end\n'), 0)
   end)

   it("967 an elseif that repeats an earlier condition", function()
      local hits = found("967", 'if a == 1 then f() elseif a == 1 then g() end\n')
      assert_equal(#hits, 1)
      assert_equal(#found("967", 'if x then f() elseif y then g() elseif x then h() end\n'), 1)
      assert_equal(#found("967", 'if a == 1 then f() elseif a == 2 then g() end\n'), 0)
   end)

   it("968 a table constructor mixing positional and keyed entries", function()
      assert_equal(#found("968", 'local t = {1, 2, a = 3}\n'), 1)
      assert_equal(#found("968", 'local t = {1, 2, 3}\nlocal u = {a = 1, b = 2}\nlocal v = {[1] = "x", [2] = "y"}\n'), 0)
   end)

   it("all three stay off by default", function()
      for _, code in ipairs({"966", "967", "968"}) do
         assert_equal(#found(code, 'if x then f(1) elseif x then f(1) end\nlocal t = {1, a = 2}\n', {}), 0)
      end
   end)
end)

describe("969-970 unbalanced assignment, parenthesized condition (#348, #360, #379)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("969 more names than values, or more values than names", function()
      local few = found("969", 'local a, b = 1\n')
      assert_equal(#few, 1)
      assert_match(few[1], "2 names, 1 value", few[1])
      assert_equal(#found("969", 'local a = 1, 2\n'), 1)
      assert_equal(#found("969", 'x, y = 1, 2, 3\n'), 1)
      assert_equal(#found("969", 'local a, b = f()\nlocal c, d = ...\nlocal e, g = 1, h()\n'), 0)
      assert_equal(#found("969", 'local a, b\nlocal c, d = 1, 2\n'), 0)
   end)

   it("970 a condition wrapped in parentheses", function()
      assert_equal(#found("970", 'if (x) then f() end\n'), 1)
      assert_equal(#found("970", 'while (x) do f() end\n'), 1)
      assert_equal(#found("970", 'repeat f() until (x)\n'), 1)
      assert_equal(#found("970", 'if (a or b) and c then f() end\nif x then f() end\n'), 0)
   end)

   it("both stay off by default", function()
      for _, code in ipairs({"969", "970"}) do
         assert_equal(#found(code, 'local a, b = 1\nif (x) then f() end\n', {}), 0)
      end
   end)
end)

describe("971-972 unused label, division by literal zero (#347, #380)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("971 a label no goto jumps to", function()
      local hits = found("971", 'for i = 1, 3 do\n  ::skip::\nend\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], "skip", hits[1])
      assert_equal(#found("971", 'for i = 1, 3 do\n  if i == 2 then goto continue end\n  f(i)\n  ::continue::\nend\n'), 0)
   end)

   it("971 labels are scoped to their function", function()
      -- inside a function body, and a goto in another function does not use it
      local hits = found("971", 'local function f()\n  ::inner::\nend\nlocal function g()\n  goto inner\n  ::inner::\nend\n')
      assert_equal(#hits, 1)
      assert_match(hits[1], "inner", hits[1])
   end)

   it("972 dividing by the literal zero", function()
      assert_equal(#found("972", 'local a = x / 0\n'), 1)
      assert_equal(#found("972", 'local b = x % 0\n'), 1)
      assert_equal(#found("972", 'local nan = 0/0\nlocal d = x / 2\nlocal e = x / y\n'), 0)
   end)

   it("both stay off by default", function()
      for _, code in ipairs({"971", "972"}) do
         assert_equal(#found(code, '::l::\nlocal a = x / 0\n', {}), 0)
      end
   end)
end)

describe("973-975 line too long, empty statement, multiple statements on a line (#354, #350, #373)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("973 a line longer than 120 characters", function()
      local long = "local s = '" .. string.rep("x", 120) .. "'\n"
      local hits = found("973", "local a = 1\n" .. long)
      assert_equal(#hits, 1)
      assert_match(hits[1], "132", hits[1])
      assert_equal(#found("973", "local s = '" .. string.rep("x", 108) .. "'\n"), 0)  -- exactly 120
   end)

   it("974 an empty statement", function()
      assert_equal(#found("974", "local a = 1;;\n"), 1)
      assert_equal(#found("974", ";\nlocal b = 2\n"), 1)
      assert_equal(#found("974", "local a = 1; local b = 2\n"), 0)  -- a separator, not an empty statement
   end)

   it("975 two statements on one line", function()
      local hits = found("975", "local a = 1; local b = 2\nprint(a, b)\n")
      assert_equal(#hits, 1)
      -- a statement whose own block sits on the same line is one statement
      assert_equal(#found("975", "if a then return end\nfor i = 1, 2 do print(i) end\n"), 0)
   end)

   it("all three stay off by default", function()
      for _, code in ipairs({"973", "974", "975"}) do
         assert_equal(#found(code, "local a = 1;; local b = 2 -- " .. string.rep("y", 130) .. "\n", {}), 0)
      end
   end)
end)

describe("976-977 trailing whitespace, mixed indentation (#353)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("976 trailing whitespace on code, comment and blank lines", function()
      assert_equal(#found("976", "local a = 1 \nlocal b = 2\t\n"), 2)
      assert_equal(#found("976", "-- note  \n"), 1)
      assert_equal(#found("976", "local a = 1\n   \nlocal b = 2\n"), 1)  -- a whitespace-only line
      assert_equal(#found("976", "local a = 1\n\nlocal b = 2\n"), 0)
      -- inside a long string the spaces are part of the value
      assert_equal(#found("976", "local s = [[\nkeep  \n]]\n"), 0)
   end)

   it("977 a space before a tab in the indentation", function()
      local hits = found("977", "if x then\n \tprint(x)\nend\n")
      assert_equal(#hits, 1)
      assert_equal(#found("977", "if x then\n\tprint(x)\n    print(x)\n\t  print(x)\nend\n"), 0)
   end)

   it("both stay off by default", function()
      for _, code in ipairs({"976", "977"}) do
         assert_equal(#found(code, "local a = 1 \nif a then\n \tprint(a)\nend\n", {}), 0)
      end
   end)
end)
