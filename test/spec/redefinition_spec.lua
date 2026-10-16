-- Opt-in lints 985-987: a local, an argument or a loop variable that is bound a second
-- time in the scope it already lives in (luacheck 411/412/413).
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_truthy = harness.assert_equal, harness.assert_truthy

local api = require "luadoctor.api"

local LINT = {category = {"lint"}}

describe("985-987 redefinition in the same scope (#344)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("985 a local redefined in the same scope", function()
      assert_equal(#found("985", "local x = 1\nlocal x = 2\nreturn x\n"), 1)
      assert_equal(#found("985", "local function f()\n  local a = 1\n  local a = 2\n  return a\nend\nreturn f()\n"), 1)
      -- different scopes are not a redefinition
      assert_equal(#found("985", "local x = 1\ndo local x = 2 end\nreturn x\n"), 0)
      -- a local and a function of the same name in one scope is still a redefinition
      assert_equal(#found("985", "local x = 1\nlocal x = 2\nlocal x = 3\nreturn x\n"), 2)
   end)

   it("986 an argument redefined by a local in the function scope", function()
      assert_equal(
         #found("986", "local function f(a)\n  local a = 1\n  return a\nend\nreturn f(2)\n"),
         1
      )
      assert_equal(
         #found("986", "local function f(a)\n  do local a = 1 end\n  return a\nend\nreturn f(2)\n"),
         0
      )
      -- ...self and ... are not named arguments
      assert_equal(#found("986", "local function f(...)\n  local ... = 1\n  return 2\nend\nreturn f()\n"), 0)
   end)

   it("987 a loop variable redefined in the loop body", function()
      assert_equal(#found("987", "local s = 0\nfor i = 1, 3 do\n  local i = 0\n  s = s + i\nend\nreturn s\n"), 1)
      assert_equal(
         #found("987", "local t = {}\nfor k, v in ipairs(t) do\n  local v = 1\n  t[#t + 1] = v\nend\nreturn t\n"),
         1
      )
      assert_equal(#found("987", "local s = 0\nfor i = 1, 3 do\n  local j = i\n  s = s + j\nend\nreturn s\n"), 0)
   end)

   it("names the variable in the message", function()
      local msgs = found("985", "local re_used = 1\nlocal re_used = 2\nreturn re_used\n")
      assert_equal(#msgs, 1)
      assert_truthy(string.find(msgs[1], "re_used", 1, true) ~= nil, msgs[1])
   end)

   it("all three stay off by default", function()
      local src = "local function f(a)\n  local q = 1\n  local q = 2\n  for i = 1, 2 do\n    local i = 0\n    a = a + i + q\n  end\n  return a\nend\nreturn f(1)\n"
      assert_equal(#found("985", src, {}), 0)
      assert_equal(#found("986", src, {}), 0)
      assert_equal(#found("987", src, {}), 0)
   end)
end)