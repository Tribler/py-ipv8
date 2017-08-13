@echo off
set failed=0
REM 1. Figure out if the user has nosetests installed.
REM    Change the test command and parameters accordingly.
echo|set /p="Starting IPv8 testsuite: "
where /q nosetests
if %ERRORLEVEL%==0 (
	echo using test runner 'nosetests'!
	set usenose=1
) else (
	echo using test runner 'python -m unittest'!
	set usenose=0
)
REM 2. Set up the python path for test code execution
set PYTHONPATH=%~dp0;%PYTHONPATH%
REM 3. Set up variables needed for test output collection
set unit_test_time=0
set total_test_count=0
set starttime=%time%
set "starttime=%starttime: =0%"
set /A starttime=(1%starttime:~0,2%-100)*360000 + (1%starttime:~3,2%-100)*6000 + (1%starttime:~6,2%-100)*100 + (1%starttime:~9,2%)
REM 4.  Loop over all of the input files and test them
for /F "eol=#" %%A in (test_classes_list.txt) do (
	call :runline %%A
	setlocal EnableDelayedExpansion
	if !failed!==1 (
		echo CRITICAL FAILURE: ABORTING
		exit /b 1
	)
	setlocal DisableDelayedExpansion
)
goto EOF

:runline
REM 5. Read and process the classes which should be tested.
set line=%1
if %usenose%==0 (
	set "fline=%line:.py:=.%"
	set "line=%fline:/=.%"
)
REM 5.a. Print the header
echo ======================================================================
echo  %line%
echo ======================================================================
REM 5.b. Pipe the output of the test command  to a subroutine
if %usenose%==1 (
	for /f "tokens=1-5" %%G in ('nosetests -s -x -v %line% ^2^>^&^1') do (
		echo %%G %%H %%I %%J %%K
		if "%%G"=="FAIL:" (
			set failed=1
		)
		if "%%G"=="ERROR:" (
			set failed=1
		)
		if "%%G"=="Ran" (
			if /I %failed% NEQ 1 (
				call :parseline "%%G" "%%H" "%%I" "%%J" "%%K"
			)
		)
	)
) else (
	for /f "tokens=1-5" %%G in ('python -m unittest --verbose %line% ^2^>^&^1') do (
		echo %%G %%H %%I %%J %%K
		if "%%G"=="FAIL:" (
			set failed=1
		)
		if "%%G"=="ERROR:" (
			set failed=1
		)
		if "%%G"=="Ran" (
			if /I %failed% NEQ 1 (
				call :parseline "%%G" "%%H" "%%I" "%%J" "%%K"
			)
		)
	)
)
exit /b

:parseline
REM 5.c. Parse the command output and extract the test time and test count for
REM      this particular class. Then proceed to add them to the totals. 
set "command=%1"
set "testcount=%2"
set "testtime=%5"

set testcount=%testcount:~1,-1%
set testtime=%testtime:~1,-2%
set testtime=%testtime:.=%
for /f "tokens=* delims=0" %%a in ("%testtime%") do (
	set testtime=%%a
)

set /A total_test_count+=%testcount%
if /I "%testtime%" NEQ "" (
	set /A unit_test_time+=%testtime%
)

exit /b

:EOF
REM 6. Show the totals.
set endtime=%time%
set "endtime=%endtime: =0%"
set /A endtime=(1%endtime:~0,2%-100)*360000 + (1%endtime:~3,2%-100)*6000 + (1%endtime:~6,2%-100)*100 + (1%endtime:~9,2%)
set /A difftime=%endtime%-%starttime%
set difftime=%difftime:~0,-2%.%difftime:~-2% seconds
set unit_test_time=%unit_test_time:~0,-3%.%unit_test_time:~-3% seconds

echo ^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>^>
echo Total time with overhead: %difftime%
echo Total time in tests:      %unit_test_time%
echo Total amount of tests:    %total_test_count%
echo ^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<^<