-- JUnit, TAP and Visual Studio report formats (#387): the library and the command line render the same bytes,
-- and each format has its expected shape.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match
local api = require "luadoctor.api"

local FIXTURE = "test/fixtures/tainted_exec/handler.lua"

local function cli_render(name)
   local out = harness.cli({"--format", name, FIXTURE})
   return (out:gsub("\n+$", ""))
end

describe("junit, tap and visual_studio formats", function()
   it("render the same through the library and the command line", function()
      local report = api.analyze({FIXTURE}, {})
      for _, name in ipairs({"junit", "tap", "visual_studio"}) do
         assert_equal(api.format(report, name), cli_render(name))
      end
   end)

   it("tap is TAP 13 with one not-ok line per finding", function()
      local out = api.format(api.analyze({FIXTURE}, {}), "tap")
      assert_match(out, "^TAP version 13\n1%.%.%d+\n", out)
      assert_match(out, "\nnot ok 1 %- test/fixtures/tainted_exec/handler%.lua:%d+:%d+ %[%d+%] ", out)
   end)

   it("junit is a testsuite with one failing testcase per finding, XML-escaped", function()
      local out = api.format(api.analyze({FIXTURE}, {}), "junit")
      assert_match(out, "^<%?xml version=\"1%.0\" encoding=\"UTF%-8\"%?>\n<testsuites>", out)
      assert_match(out, "<testsuite name=\"lua%-doctor\" tests=\"%d+\" failures=\"%d+\">", out)
      assert_match(out, "<testcase classname=\"test/fixtures/tainted_exec/handler%.lua\" name=\"[^\"]+\"><failure type=\"%d+\" message=\"", out)
      assert_equal(out:find("<failure[^>]*<", 1) == nil, true, "attribute values must be escaped")
   end)

   it("visual_studio is file(line,col) : severity code: message", function()
      local out = api.format(api.analyze({FIXTURE}, {}), "visual_studio")
      assert_match(out, "^test/fixtures/tainted_exec/handler%.lua%(%d+,%d+%) : %a+ %d+: ", out)
   end)

   it("an unknown format names all seven", function()
      local _, err = api.format(api.analyze({FIXTURE}, {}), "nope")
      assert_match(err, "plain, json, sarif, html, junit, tap or visual_studio", err)
   end)
end)
