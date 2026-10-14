-- Whole-program: a require written inline inside an expression, not bound to a
-- local first. `require("lib").echo(x)` used as a value (an argument to a sink)
-- must carry the taint of `x` through lib's return, as the bound form does.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

local DIR = "test/fixtures/whole_program/inline_require"

local function scan(files)
   local paths = {}
   for _, name in ipairs(files) do paths[#paths + 1] = DIR .. "/" .. name end
   return api.analyze(paths, {std = "cgilua", whole_program = true})
end

local function sinks(result, code)
   local out = {}
   for _, finding in ipairs(result) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

describe("whole-program taint through an inline require", function()
   it("reports a tainted value returned by an inline-required module reaching os.execute", function()
      local found = sinks(scan({"handler.lua", "lib.lua"}), "709")
      assert_equal(#found, 1, "one 709 for the inline require(...).echo(...) flow")
      assert_true(found[1].file:find("handler.lua", 1, true) ~= nil,
         "the finding belongs to the file holding the sink")
      assert_equal(found[1].line, 2, "at the os.execute line")
   end)
end)
