local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true
local api = require "luadoctor.api"

local LINT = {category = {"lint"}}

describe("982-984 unused local, argument and loop variable (#340)", function()
   local function found(code, source, opts)
      local out = {}
      for _, finding in ipairs(api.check_source(source, opts or LINT)) do
         if finding.code == code then out[#out + 1] = finding.message end
      end
      return out
   end

   it("982 a local assigned but never read", function()
      assert_equal(#found("982", "local x = 1\nreturn 2\n"), 1)
      assert_equal(#found("982", "local x = 1\nreturn x\n"), 0)
      -- a local function that is called is used
      assert_equal(#found("982", "local function f()\n  return 1\nend\nreturn f()\n"), 0)
      assert_equal(#found("982", "local function f()\n  return 1\nend\n"), 1)
      -- declared but never assigned and never read either
      assert_equal(#found("982", "local y\nreturn 2\n"), 1)
   end)

   it("983 a function argument never read", function()
      assert_equal(#found("983", "local function f(used, unused_name)\n  return used\nend\nreturn f(1, 2)\n"), 1)
      assert_equal(#found("983", "local function f(a, b)\n  return a + b\nend\nreturn f(1, 2)\n"), 0)
      -- `...` and `self` are never flagged: they are not named parameters
      assert_equal(#found("983", "local function f(...)\n  return 1\nend\nreturn f()\n"), 0)
   end)

   it("984 a loop variable never read", function()
      assert_equal(
         #found("984", "local t = {}\nfor i, v in ipairs(t) do\n  t[#t + 1] = i\nend\nreturn t\n"),
         1
      )
      assert_equal(
         #found("984", "local t = {}\nfor i, v in ipairs(t) do\n  t[#t + 1] = i + v\nend\nreturn t\n"),
         0
      )
      -- the numeric for loop counter
      assert_equal(#found("984", "local s = 0\nfor i = 1, 3 do\n  s = s + 1\nend\nreturn s\n"), 1)
      assert_equal(#found("984", "local s = 0\nfor i = 1, 3 do\n  s = s + i\nend\nreturn s\n"), 0)
   end)

   it("names the variable in the message", function()
      local msgs = found("982", "local never_read = 1\nreturn 2\n")
      assert_equal(#msgs, 1)
      assert_true(string.find(msgs[1], "never_read", 1, true) ~= nil, msgs[1])
   end)

   it("all three stay off by default", function()
      local src = "local function f(a)\n  local q = 1\n  for _i in ipairs({}) do end\n  return 2\nend\nreturn f(1)\n"
      assert_equal(#found("982", src, {}), 0)
      assert_equal(#found("983", src, {}), 0)
      assert_equal(#found("984", src, {}), 0)
   end)
end)
