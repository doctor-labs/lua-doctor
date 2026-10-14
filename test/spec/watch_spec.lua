local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local watch = require "luadoctor.cli.watch"

-- A fake file system: `times` maps path to its stamp, a missing key is a deleted file.
local function fake_mtimes(times)
   return function(files)
      local now = {}
      for _, path in ipairs(files) do now[path] = times[path] end
      return now
   end
end

describe("lua-doctor watch mode", function()
   it("treats every file as changed on the first poll", function()
      local times = {["a.lua"] = "1", ["b.lua"] = "1"}
      local changed = watch.diff({}, {"a.lua", "b.lua"}, fake_mtimes(times))
      assert_equal(table.concat(changed, ","), "a.lua,b.lua")
   end)

   it("reports only the file whose stamp moved since the last poll", function()
      local times = {["a.lua"] = "1", ["b.lua"] = "1"}
      local _, snapshot = watch.diff({}, {"a.lua", "b.lua"}, fake_mtimes(times))
      times["b.lua"] = "2"
      local changed = watch.diff(snapshot, {"a.lua", "b.lua"}, fake_mtimes(times))
      assert_equal(table.concat(changed, ","), "b.lua")
   end)

   it("reports a new file and stays silent about a deleted one", function()
      local times = {["a.lua"] = "1", ["gone.lua"] = "1"}
      local _, snapshot = watch.diff({}, {"a.lua", "gone.lua"}, fake_mtimes(times))
      times["gone.lua"] = nil
      times["new.lua"] = "1"
      local changed = watch.diff(snapshot, {"a.lua", "new.lua"}, fake_mtimes(times))
      assert_equal(table.concat(changed, ","), "new.lua")
   end)

   it("polls until told to stop, rescanning only what changed each time", function()
      local times = {["a.lua"] = "1", ["b.lua"] = "1"}
      local scans, polls = {}, 0
      local exit_code = watch.run({
         files = function() return {"a.lua", "b.lua"} end,
         mtimes = fake_mtimes(times),
         on_change = function(changed) scans[#scans + 1] = table.concat(changed, ",") end,
         wait = function()
            polls = polls + 1
            if polls == 1 then times["b.lua"] = "2" end
            return polls < 3
         end,
      })
      assert_equal(exit_code, 0)
      assert_equal(#scans, 2)
      assert_equal(scans[1], "a.lua,b.lua")
      assert_equal(scans[2], "b.lua")
   end)

   it("does not rescan when nothing moved", function()
      local times = {["a.lua"] = "1"}
      local scans, polls = 0, 0
      watch.run({
         files = function() return {"a.lua"} end,
         mtimes = fake_mtimes(times),
         on_change = function() scans = scans + 1 end,
         wait = function()
            polls = polls + 1
            return polls < 4
         end,
      })
      assert_true(scans == 1, "expected one scan, got " .. scans)
   end)
end)

describe("lua-doctor watch flag", function()
   it("refuses to combine with --staged", function()
      local out, code = harness.cli({"--watch", "--staged", "."})
      assert_equal(code, 2, out)
   end)
end)
