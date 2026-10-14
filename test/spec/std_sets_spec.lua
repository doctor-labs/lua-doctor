-- The test, love, rockspec and roblox std sets (#356): each defines its own
-- globals on top of the default std, as a platform profile does, so the
-- undefined-variable lint (951) stops reporting them.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

local api = require "luadoctor.api"

local function undefined_of(source, std)
   local out = {}
   for _, finding in ipairs(api.check_source(source, {category = {"lint"}, std = std})) do
      if finding.code == "951" then out[#out + 1] = finding.name end
   end
   return table.concat(out, ",")
end

describe("the busted std set (#356)", function()
   local source = 'describe("x", function() it("y", function() assert.is_true(true) end) end)\n'

   it("defines the busted test globals", function()
      assert_equal(undefined_of(source, "+busted"), "")
   end)

   it("without it the busted globals are undefined", function()
      assert_equal(undefined_of(source, nil), "describe,it")
   end)
end)

describe("the love std set (#356)", function()
   it("defines the love global and its fields", function()
      assert_equal(undefined_of("love.graphics.print('x')\n", "+love"), "")
   end)

   it("keeps the default globals defined", function()
      assert_equal(undefined_of("print(love.timer)\n", "+love"), "")
   end)
end)

describe("the rockspec std set (#356)", function()
   it("defines the rockspec fields", function()
      assert_equal(undefined_of("print(rockspec_format, dependencies)\n", "+rockspec"), "")
   end)
end)

describe("the roblox std set (#356)", function()
   it("defines the Roblox classes and task library", function()
      assert_equal(undefined_of("local p = Vector3.new(1, 2, 3)\ntask.wait(Instance.new('Part'))\n", "+roblox"), "")
   end)

   it("keeps the default globals defined", function()
      assert_equal(undefined_of("print(task)\n", "+roblox"), "")
   end)
end)

describe("std sets combine (#356)", function()
   it("several sets named together all apply", function()
      assert_equal(undefined_of("describe(love.graphics, rockspec_format)\n", "+busted+love+rockspec"), "")
   end)
end)
