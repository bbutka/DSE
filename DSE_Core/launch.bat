@echo off
:: DSE Tool launcher — requires Python 3.12 with clingo installed
:: Run from D:\DSE\DSE_ADD

set PY="C:\Users\bbutk\AppData\Local\Programs\Python\Python312\python.exe"

%PY% -m dse_tool %*
