-- Taint through method calls (#327) and through functions held as values (#328).
--
-- `M:run(x)`, `M.run(x)`, a callback handed to a helper and a function stored in
-- a table are the shapes embedded Lua is written in. Each flow has a clean twin
-- that passes a constant, so a finding cannot come from a call being resolved
-- alone.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luadoctor.api"

local function has(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return true end
   end
   return false
end

local function scan(body)
   return api.check_source("local x = luci.http.formvalue(\"x\")\n" .. body,
      {std = "openwrt+luci"})
end

describe("taint through method calls (#327)", function()
   it("request data passed to a colon-defined method reaches its sink", function()
      assert_true(has(scan([[
local M = {}
function M:run(cmd) os.execute(cmd) end
M:run(x)
]]), "709"), "expected 709")
   end)

   it("request data passed to a dot-defined field function reaches its sink", function()
      assert_true(has(scan([[
local M = {}
function M.go(cmd) os.execute(cmd) end
M.go(x)
]]), "709"), "expected 709")
   end)

   it("a method defined with a dot and called with a colon takes the receiver as its first formal", function()
      assert_true(has(scan([[
local M = {}
function M.go(self, cmd) os.execute(cmd) end
M:go(x)
]]), "709"), "expected 709")
   end)

   it("a method defined in a table constructor is followed", function()
      assert_true(has(scan([[
local M = {run = function(self, cmd) os.execute(cmd) end}
M:run(x)
]]), "709"), "expected 709")
   end)

   it("a constant passed to the same method is not a 709", function()
      assert_true(not has(scan([[
local M = {}
function M:run(cmd) os.execute(cmd) end
M:run("ls")
]]), "709"), "constant argument must stay silent")
   end)

   it("the value a method returns carries the taint of its argument", function()
      assert_true(has(scan([[
local M = {}
function M:id(a) return a end
os.execute(M:id(x))
]]), "709"), "expected 709")
   end)
end)

describe("taint through functions passed as values (#328)", function()
   it("a callback handed to a helper receives the helper's argument", function()
      assert_true(has(scan([[
local function cb(c) os.execute(c) end
local function apply(f, v) f(v) end
apply(cb, x)
]]), "709"), "expected 709")
   end)

   it("a function stored in a table field is followed", function()
      assert_true(has(scan([[
local function cb(c) os.execute(c) end
local handlers = {run = cb}
handlers.run(x)
]]), "709"), "expected 709")
   end)

   it("a function literal passed as a callback is followed", function()
      assert_true(has(scan([[
local function apply(f, v) f(v) end
apply(function(c) os.execute(c) end, x)
]]), "709"), "expected 709")
   end)

   it("the return value of a callback carries the argument's taint", function()
      assert_true(has(scan([[
local function ap(f, v) return f(v) end
os.execute(ap(function(q) return q end, x))
]]), "709"), "expected 709")
   end)

   it("a constant passed through the same helper is not a 709", function()
      assert_true(not has(scan([[
local function cb(c) os.execute(c) end
local function apply(f, v) f(v) end
apply(cb, "ls")
]]), "709"), "constant argument must stay silent")
   end)
end)
