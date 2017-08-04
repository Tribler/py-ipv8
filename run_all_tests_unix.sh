#!/bin/bash
test_files=""
test_files="$test_files test/keyvault/test_serialization.py:TestSerialization"
test_files="$test_files test/keyvault/test_signature.py:TestSignatures"
test_files="$test_files test/messaging/anonymization/test_community.py:TestTunnelCommunity"
test_files="$test_files test/messaging/anonymization/test_hiddenservices.py:TestHiddenServices"
export PYTHONPATH='.'
TIMEFORMAT="Total time with overhead: %R seconds"
unit_test_time=0
total_test_count=0
time {
for f in $test_files; do
echo "======================================================================"
echo " $f"
echo "======================================================================"
set -o pipefail
t=$(tempfile)
nosetests -s -x -v "$f" 2> >(tee $t >&2)
exit_status=$?
if [ $exit_status -ne 0 ] ; then echo "CRITICAL FAILURE: ABORTING" ; break ; fi
last_time=$(cat $t | grep "Ran [0-9]\+ tests in [0-9]\+\.[0-9]\+s" | grep -o "[0-9]\+\.[0-9]\+")
unit_test_time=`echo $unit_test_time + $last_time | bc`
last_test_count=$(cat $t | grep "Ran [0-9]\+ tests in [0-9]\+\.[0-9]\+s" | grep -o " [0-9]\+ ")
total_test_count=$((total_test_count + last_test_count))
done
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
}
echo "Total time in tests:      $unit_test_time seconds"
echo "Total amount of tests:    $total_test_count"
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
