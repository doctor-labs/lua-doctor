local function go(host)
   os.execute(require("lib").echo(http.formvalue(host)))
end

return go
