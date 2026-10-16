local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

-- A file with a finding (709: untrusted os.getenv reaching os.execute) and one
-- without. Two files, so a run can mix cache hits with fresh analysis.
local FIRING = 'local host = os.getenv("HOST")\nos.execute("ping -c 1 " .. host)\n'
local QUIET = 'local host = "localhost"\nprint(host)\n'

local function write(path, content)
   local handle = assert(io.open(path, "wb"))
   handle:write(content)
   handle:close()
end

local function remove(dir)
   os.execute("rm -rf " .. string.format("%q", dir))
end

describe("results cache (--cache)", function()
   it("reports exactly what an uncached run reports, on the first run and on a run served from the cache", function()
      local dir = harness.scratch_dir("results_cache")
      local a, b, cache = dir .. "/a.lua", dir .. "/b.lua", dir .. "/cache.json"
      write(a, FIRING)
      write(b, QUIET)
      local plain, plain_code = harness.cli({a, b})
      local first, first_code = harness.cli({"--cache", cache, a, b})
      local second, second_code = harness.cli({"--cache", cache, a, b})
      assert_equal(first, plain, "first cached run")
      assert_equal(first_code, plain_code, "first cached run exit code")
      assert_equal(second, plain, "second run, served from the cache")
      assert_equal(second_code, plain_code, "second run exit code")
      remove(dir)
   end)

   it("re-analyzes an edited file and keeps serving the unchanged one", function()
      local dir = harness.scratch_dir("results_cache")
      local a, b, cache = dir .. "/a.lua", dir .. "/b.lua", dir .. "/cache.json"
      write(a, FIRING)
      write(b, FIRING)
      harness.cli({"--cache", cache, a, b})
      write(a, QUIET)
      local cached, cached_code = harness.cli({"--cache", cache, a, b})
      local plain, plain_code = harness.cli({a, b})
      assert_equal(cached, plain, "the edited file's findings come from its new content")
      assert_equal(cached_code, plain_code, "exit code after the edit")
      remove(dir)
   end)

   it("does not serve findings from a run with different options", function()
      local dir = harness.scratch_dir("results_cache")
      local a, cache = dir .. "/a.lua", dir .. "/cache.json"
      write(a, FIRING)
      harness.cli({"--cache", cache, a})
      local cached, cached_code = harness.cli({"--cache", cache, "--ignore", "709", a})
      local plain, plain_code = harness.cli({"--ignore", "709", a})
      assert_equal(cached, plain, "--ignore 709 is applied, not replayed from the default run")
      assert_equal(cached_code, plain_code, "exit code with --ignore 709")
      remove(dir)
   end)

   it("reports the same with --jobs and with --whole-program", function()
      local dir = harness.scratch_dir("results_cache")
      local a, b, cache = dir .. "/a.lua", dir .. "/b.lua", dir .. "/cache.json"
      write(a, FIRING)
      write(b, QUIET)
      local plain = harness.cli({a, b})
      assert_equal(harness.cli({"--cache", cache, "--jobs", "2", a, b}), plain, "--jobs 2")
      assert_equal(harness.cli({"--cache", cache, "--whole-program", a, b}),
         harness.cli({"--whole-program", a, b}), "--whole-program")
      remove(dir)
   end)
end)
