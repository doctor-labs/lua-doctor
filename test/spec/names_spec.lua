-- 713: a call to an undefined name that is one typo from an execution sink (#330).
--
-- The misspelled call fails at run time and matches no declared sink, so the
-- finding the real API would have produced is silently missing. Every case that
-- should stay quiet is a name the std or the file defines.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luadoctor.api"

local function codes_of(source, std)
   local seen = {}
   for _, finding in ipairs(api.check_source(source, {std = std})) do
      seen[finding.code] = (seen[finding.code] or 0) + 1
   end
   return seen
end

describe("a misspelled execution sink (#330)", function()
   it("os.execte is reported as 713 naming os.execute", function()
      local found
      for _, finding in ipairs(api.check_source("os.execte(cmd)\n")) do
         if finding.code == "713" then found = finding end
      end
      assert_true(found, "expected a 713")
      assert_true(found.message:find("os.execute", 1, true), "the message names the intended sink")
   end)

   it("a misspelled bare global sink is reported", function()
      assert_true(codes_of("loadstrng(code)\n")["713"], "expected a 713")
   end)

   it("a transposition counts as one edit", function()
      assert_true(codes_of("io.popne(cmd)\n")["713"], "expected a 713")
   end)

   it("the correctly spelled sink is not a 713", function()
      assert_true(not codes_of("os.execute(cmd)\n")["713"], "os.execute is the sink")
   end)

   it("a real function one edit from a sink is not a 713", function()
      assert_true(not codes_of("local f = io.open(path)\n")["713"], "io.open exists")
   end)

   it("a global the file defines is not a 713", function()
      assert_true(not codes_of("function loadstrinx() end\nloadstrinx(cmd)\n")["713"],
         "defined in this file")
   end)

   it("a platform table the profile leaves open is not guessed at", function()
      assert_true(not codes_of("luci.sys.calll(cmd)\n", "+luci")["713"], "luci fields are unknown")
   end)

   it("a name two edits from a sink is not a 713", function()
      assert_true(not codes_of("readfile(path)\n")["713"], "readfile is not a misspelled loadfile")
   end)

   it("a name far from every sink is not a 713", function()
      assert_true(not codes_of("os.frobnicate(cmd)\n")["713"], "nothing it could be")
   end)
end)

describe("a local that shadows a sink's library (#331)", function()
   it("local os = require(other) is reported as 714", function()
      assert_true(codes_of('local os = require("fakeos")\nos.execute(cmd)\n')["714"], "expected a 714")
   end)

   it("a local io bound to some other value is reported", function()
      assert_true(codes_of("local x = {}\nlocal io = x\n")["714"], "expected a 714")
   end)

   it("localising the library itself is not reported", function()
      assert_true(not codes_of("local os = os\nos.execute(cmd)\n")["714"], "local os = os")
      assert_true(not codes_of("local os = _G.os\n")["714"], "local os = _G.os")
      assert_true(not codes_of('local os = require "os"\n')["714"], 'require "os"')
   end)

   it("a table that carries the library's functions is not reported", function()
      assert_true(not codes_of("local io = {popen = f}\n")["714"], "table constructor")
   end)

   it("an unrelated local is not reported", function()
      assert_true(not codes_of('local fakeos = require("fakeos")\n')["714"], "different name")
   end)

   it("a local that merely names a platform table is not reported", function()
      assert_true(not codes_of('local luci = require("other")\n', "+luci")["714"],
         "luci is not a standard library")
   end)

   it("a second shadow of the same name is reported once", function()
      local report = api.check_source('local os = require("fakeos")\nlocal os = os\n')
      local n = 0
      for _, finding in ipairs(report) do if finding.code == "714" then n = n + 1 end end
      assert_true(n == 1, "expected one 714, got " .. n)
   end)
end)

describe("714 and a localised require", function()
   it("local os = require 'os' is not reported when require is itself a local", function()
      assert_true(not codes_of('local require = require\nlocal os = require "os"\n')["714"],
         "the corpus's luci-lib-httpclient receiver.lua idiom")
   end)
end)
