-- Watch mode: poll Lua files for changes with a stdlib-only loop and hand the
-- changed ones to a callback. No luv or inotify binding: the stamp of a file is
-- its mtime and size, read with `stat` once per poll.
local walk = require "luadoctor.cli.walk"

local watch = {}

local SECONDS_BETWEEN_POLLS = 1
-- ponytail: stat runs once per file per poll (batched by argv size). inotify or
-- FSEvents would avoid the re-walk on a very large tree; add them when polling is slow.
local STAT_BATCH = 200

--- One poll step. `previous` is the snapshot from the last poll (path -> stamp),
-- `files` the paths to look at now, `mtimes(files)` returns path -> stamp for
-- those that exist. Returns the sorted list of paths whose stamp is new or moved,
-- and the snapshot to pass to the next poll. A deleted file is simply absent.
function watch.diff(previous, files, mtimes)
   local now = mtimes(files)
   local changed, snapshot = {}, {}
   for _, path in ipairs(files) do
      local stamp = now[path]
      if stamp then
         snapshot[path] = stamp
         if previous[path] ~= stamp then changed[#changed + 1] = path end
      end
   end
   table.sort(changed)
   return changed, snapshot
end

--- The poll loop. `deps.files()` lists the paths, `deps.mtimes(files)` stamps
-- them, `deps.on_change(changed)` runs for each non-empty change set, and
-- `deps.wait()` pauses between polls and returns false to stop. The real caller
-- never stops it: an interrupt (Ctrl-C) ends the process, which holds no state
-- that needs flushing.
function watch.run(deps)
   local snapshot = {}
   repeat
      local changed
      changed, snapshot = watch.diff(snapshot, deps.files(), deps.mtimes)
      if #changed > 0 then deps.on_change(changed) end
   until not deps.wait()
   return 0
end

local function quote(text)
   return "'" .. (text:gsub("'", "'\\''")) .. "'"
end

local stat_command
local function stat_format()
   if not stat_command then
      local pipe = io.popen("uname -s")
      local system = pipe and pipe:read("*l") or ""
      if pipe then pipe:close() end
      -- BSD stat (macOS) and GNU stat spell mtime, size and name differently.
      stat_command = system == "Darwin" and "stat -f '%m %z %N'" or "stat -c '%Y %s %n'"
   end
   return stat_command
end

-- Real stamps: mtime and size from one `stat` per batch. A path that cannot be
-- stat'ed gets no stamp, which the diff reads as deleted.
local function system_mtimes(files)
   local times = {}
   local command = stat_format()
   for first = 1, #files, STAT_BATCH do
      local batch = {}
      for i = first, math.min(first + STAT_BATCH - 1, #files) do
         batch[#batch + 1] = quote(files[i])
      end
      local pipe = io.popen(command .. " " .. table.concat(batch, " ") .. " 2>/dev/null")
      if pipe then
         for line in pipe:lines() do
            local mtime, size, path = line:match("^(%d+) (%d+) (.+)$")
            if path then times[path] = mtime .. " " .. size end
         end
         pipe:close()
      end
   end
   return times
end

--- Watch `paths` until interrupted. `on_change(changed)` gets each batch of
-- changed files, the first batch being every file.
function watch.loop(paths, on_change)
   return watch.run({
      files = function()
         local files = walk.collect(paths)
         return files or {}
      end,
      mtimes = system_mtimes,
      on_change = on_change,
      wait = function()
         os.execute("sleep " .. SECONDS_BETWEEN_POLLS)
         return true
      end,
   })
end

return watch
