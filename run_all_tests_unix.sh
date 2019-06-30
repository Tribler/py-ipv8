#!/bin/bash

# 1. Read the classes which should be tested.
test_files="$(grep ^[^#] test_classes_list.txt)"


# 2. Figure out if the user has nosetests installed.
#    Change the test command and parameters accordingly.
tty -s && tput bold

# 2.1 Check for python interpreter version
if [ -x "$(command -v python2)" ]; then
    interpreter="python2"
else
    echo "No python2 command found! Will use the default python command."
    interpreter="python"
fi

echo -n "Starting IPv8 testsuite: "
if nosetests --version >>/dev/null 2>&1; then
    echo "using test runner 'nosetests'!"
    # Use nosetests2 if available and if not, try version possibly incompatible with python2
    if [ -x "$(command -v nosetests2)" ]; then
        test_command="nosetests2"
    else
        test_command="nosetests"
    fi
    test_command+=" -s -x -v"
else
    echo "using test runner '$interpreter -m unittest'!"
    test_command="$interpreter -m unittest --verbose"
    test_files="${test_files//\//.}"
    test_files="${test_files//.py:/.}"
fi
tty -s && tput sgr0

# 3. Set up the python path for test code execution
export PYTHONPATH='.'

# 4. Set up variables needed for test output collection
TIMEFORMAT="Total time with overhead: %R seconds"
unit_test_time=0
total_test_count=0
time {
# 5. Loop over all of the input files and test them
for f in $test_files; do
# 5.a. Print the header
echo "======================================================================"
echo " $f"
echo "======================================================================"
# 5.b. Pipe the output of the test command to a temporary file: we need to
#      do this, otherwise we lose the real-time tester output.
t=$(mktemp)
set -o pipefail
$test_command "$f" 2> >(tee $t >&2)
exit_status=$?
if [ $exit_status -ne 0 ] ; then tty -s && tput rev; tty -s && tput setaf 1; echo "CRITICAL FAILURE: ABORTING"; tty -s && tput sgr0; break; fi
# 5.c. Parse the command output and extract the test time and test count for
#      this particular class. Then proceed to add them to the totals. Note that
#      we need 'bc' for the time as these are floating point numbers.
last_time=$(cat $t | grep "Ran [0-9]\+ tests\? in [0-9]\+\.[0-9]\+s" | grep -o "[0-9]\+\.[0-9]\+")
unit_test_time=`echo $unit_test_time + $last_time | bc`
last_test_count=$(cat $t | grep "Ran [0-9]\+ tests\? in [0-9]\+\.[0-9]\+s" | grep -o " [0-9]\+ ")
total_test_count=$((total_test_count + last_test_count))
done
# 6. Show the totals. Note that '}' is the end of the 'time' command, which
#    will print 'TIMEFORMAT'.
tty -s && tput bold
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
}
echo "Total time in tests:      $unit_test_time seconds"
echo "Total amount of tests:    $total_test_count"
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
tty -s && tput sgr0

# 7. Exit the script with the test runner status.
exit $exit_status
