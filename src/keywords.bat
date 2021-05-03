@setlocal
@echo off
goto :_START_
@rem:: source: "https://github.com/microsoft/terminal/issues/217#issuecomment-737594785"

:set_real_dp0
@rem:: ref: "https://stackoverflow.com/questions/19781569/cmd-failure-of-d0-when-call-quotes-the-name-of-the-batch-file"
@rem:: ref: "https://stackoverflow.com/questions/12141482/what-is-the-reason-for-batch-file-path-referenced-with-dp0-sometimes-changes-o/26851883#26851883"
@rem:: ref: "https://www.dostips.com/forum/viewtopic.php?f=3&t=5057"
set dp0=%~dp0
set "dp0=%dp0:~0,-1%" &@rem:: clip trailing path separator
goto :eof

:_START_
call :set_real_dp0
set "_prog=python.exe"

@rem:: set title back to that of what's being used in WinTerminal (lazy solution)
endlocal & goto #_undefined_# 2>nul || "%_prog%" try_keywords.py --time --log "../docs/logs/unhash_keywordsauto_cmd.log" %* & title cmd majiro-py