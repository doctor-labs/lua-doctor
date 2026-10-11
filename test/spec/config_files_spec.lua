-- Per-file config overrides (#385): `files = {["<glob>"] = {disable = {...}, severity = {...}}}` like luacheck's files table.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_match, harness.assert_no_match

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function with_config(tag, text, args)
   local dir = harness.scratch_dir(tag)
   local path = dir .. "/lua-doctor.config.lua"
   local f = assert(io.open(path, "w"))
   f:write(text)
   f:close()
   local full = {"--config", path}
   for _, a in ipairs(args) do full[#full + 1] = a end
   local out, code = harness.cli(full)
   os.execute("rm -rf " .. string.format("%q", dir))
   return out, code
end

describe("per-file config overrides", function()
   it("disables a code only in files matching the glob", function()
      local out, code = with_config("files_disable", "return {files = {['test/fixtures/tainted_exec/**'] = {disable = {'709'}}}}", {TAINTED})
      assert_equal(code, 0, out)
      assert_no_match(out, "%[709%]", out)
      local out2 = with_config("files_other", "return {files = {['vendor/**'] = {disable = {'709'}}}}", {TAINTED})
      assert_match(out2, "%[709%]", out2)
   end)

   it("overrides a severity only in matching files", function()
      local out = with_config("files_sev", "return {files = {['**/handler.lua'] = {severity = {['709'] = 'low'}}}}", {TAINTED})
      assert_match(out, "%[709%] low", out)
   end)

   it("a single star does not cross a directory", function()
      local out = with_config("files_star", "return {files = {['test/*/handler.lua'] = {disable = {'709'}}}}", {TAINTED})
      assert_match(out, "%[709%]", out)
   end)

   it("rejects an unknown key inside an override and a bad code", function()
      local out, code = with_config("files_bad", "return {files = {['x/**'] = {std = 'max'}}}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "files%['x/%*%*'%]: unknown key 'std': expected disable, severity", out)
      local out2, code2 = with_config("files_badcode", "return {files = {['x/**'] = {severity = {['799'] = 'low'}}}}", {TAINTED})
      assert_equal(code2, 2, out2)
      assert_match(out2, "'799' is not a lua%-doctor code", out2)
   end)
end)
