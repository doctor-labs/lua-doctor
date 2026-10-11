-- Which function bodies can a call reach?
--
-- A call in this file is bound to a body when the callee is a name that holds a
-- function, a table field that holds one (`M.run(x)`, `M:run(x)`), or a
-- parameter that a caller passed a function for (`apply(cb, x)` ... `f(v)`).
-- The taint passes ask this one module, so the call graph (argument flow) and
-- the return-value pass agree on what a call means.
--
-- Everything here is syntactic and per file. A table is named by the variable
-- holding it (a local's var object, or "global:<name>" for a global), and only
-- literal field names are followed, so `M[name](x)` stays unresolved: guessing
-- a callee is a finding about a function nobody wrote.
local fn_targets = {}

local MAX_TARGETS = 8
local MAX_ROUNDS = 4
local MAX_DEPTH = 8

local cache = setmetatable({}, {__mode = "k"})

local function table_key(base)
   if type(base) ~= "table" or base.tag ~= "Id" then return nil end
   if base.var then return base.var end
   if type(base[1]) == "string" then return "global:" .. base[1] end
end

local function add_unique(list, fn)
   for _, existing in ipairs(list) do
      if existing == fn then return false end
   end
   if #list >= MAX_TARGETS then return false end
   list[#list + 1] = fn
   return true
end

local resolve_value

-- Function nodes a value expression can be: a function literal, a name holding
-- one, a field holding one, a parameter a caller bound one to.
resolve_value = function(index, node, item, depth)
   local out = {}
   if type(node) ~= "table" or depth > MAX_DEPTH then return out end

   if node.tag == "Function" then
      out[1] = node
   elseif node.tag == "Paren" then
      return resolve_value(index, node[1], item, depth + 1)
   elseif node.tag == "Id" then
      if node.var then
         for _, value in ipairs(item and item.used_values and item.used_values[node.var] or {}) do
            for _, fn in ipairs(resolve_value(index, value.node, value.item or item, depth + 1)) do
               add_unique(out, fn)
            end
         end
         for _, fn in ipairs(index.params[node.var] or {}) do add_unique(out, fn) end
      else
         local fn = index.globals[node[1]]
         if fn then out[1] = fn end
      end
   elseif node.tag == "Index" and node[2] and node[2].tag == "String" then
      local fields = index.fields[table_key(node[1])]
      local fn = fields and fields[node[2][1]]
      if fn then out[1] = fn end
   end
   return out
end

--- Function bodies a call's callee expression can reach.
-- `node` is the Call/Invoke node.
function fn_targets.targets(index, node, item)
   local out = {}
   local callee = node[1]
   if node.tag == "Invoke" then
      local method = node[2] and node[2][1]
      local fields = index.fields[table_key(callee)]
      local fn = fields and type(method) == "string" and fields[method]
      if fn then out[1] = fn end
   else
      out = resolve_value(index, callee, item, 0)
   end
   return out
end

-- The argument nodes a call passes, receiver first for a method call, so they
-- line up with the callee's formals whether it was written `function M:m(x)`
-- (formals: self, x) or `function M.m(self, x)`.
function fn_targets.effective_args(node)
   local args = {}
   if node.tag == "Invoke" then
      args[1] = node[1]
      for i = 3, #node do args[#args + 1] = node[i] end
   else
      for i = 2, #node do args[#args + 1] = node[i] end
   end
   return args
end

local function each_call(chstate, visit)
   local function walk(node, item, depth)
      if type(node) ~= "table" or depth > 64 or node.tag == "Function" then return end
      if node.tag == "Call" or node.tag == "Invoke" then visit(node, item) end
      for _, child in ipairs(node) do
         if type(child) == "table" then walk(child, item, depth + 1) end
      end
   end
   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            walk(item.node, item, 0)
         elseif item.tag == "Local" or item.tag == "Set" then
            for _, value in ipairs(item.rhs or {}) do walk(value, item, 0) end
         end
      end
   end
end

--- The per-file index: global functions, functions held by table fields, and
-- the functions callers pass for a parameter. Built once per file.
function fn_targets.index(chstate)
   if cache[chstate] then return cache[chstate] end
   local index = {globals = {}, fields = {}, params = {}}
   cache[chstate] = index

   local function set_field(base, name, fn)
      local key = table_key(base)
      if not key then return end
      local fields = index.fields[key]
      if not fields then
         fields = {}
         index.fields[key] = fields
      end
      -- Two different bodies for one field is ambiguous: not followed.
      if fields[name] == nil or fields[name] == fn then
         fields[name] = fn
      else
         fields[name] = false
      end
   end

   -- Declarations: `function f()`, `function M.f()`, `M.f = cb`, `M = {f = ...}`.
   -- Repeated until stable, because `M.f = cb` needs `cb` and `cb` may be a
   -- global declared later in the file.
   for _ = 1, 2 do
      for _, line in ipairs(chstate.lines) do
         for _, item in ipairs(line.items) do
            if (item.tag == "Set" or item.tag == "Local") and item.lhs and item.rhs then
               for i, lhs in ipairs(item.lhs) do
                  local rhs = item.rhs[i]
                  if type(lhs) == "table" and type(rhs) == "table" then
                     if lhs.tag == "Id" and not lhs.var and rhs.tag == "Function"
                           and type(lhs[1]) == "string" then
                        index.globals[lhs[1]] = rhs
                     elseif lhs.tag == "Index" and lhs[2] and lhs[2].tag == "String" then
                        local fn = resolve_value(index, rhs, item, 0)[1]
                        if fn then set_field(lhs[1], lhs[2][1], fn) end
                     elseif lhs.tag == "Id" and rhs.tag == "Table" then
                        for _, pair in ipairs(rhs) do
                           if pair.tag == "Pair" and pair[1] and pair[1].tag == "String" then
                              local fn = resolve_value(index, pair[2], item, 0)[1]
                              if fn then set_field(lhs, pair[1][1], fn) end
                           end
                        end
                     end
                  end
               end
            end
         end
      end
   end

   -- Parameters: `apply(cb, x)` binds `cb`'s body to apply's first formal.
   for _ = 1, MAX_ROUNDS do
      local changed = false
      each_call(chstate, function(node, item)
         local args = fn_targets.effective_args(node)
         for _, fn in ipairs(fn_targets.targets(index, node, item)) do
            local formals = fn[1] or {}
            for i, arg in ipairs(args) do
               local formal = formals[i]
               if formal and formal.var then
                  for _, passed in ipairs(resolve_value(index, arg, item, 0)) do
                     local held = index.params[formal.var]
                     if not held then
                        held = {}
                        index.params[formal.var] = held
                     end
                     if add_unique(held, passed) then changed = true end
                  end
               end
            end
         end
      end)
      if not changed then break end
   end

   return index
end

return fn_targets
