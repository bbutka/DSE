import clingo
ctl = clingo.Control()
ctl.add("base", [], "#script(python)\ndef f(): return 1\n#end.")
ctl.ground([("base", [])])
print("Python scripting works!")