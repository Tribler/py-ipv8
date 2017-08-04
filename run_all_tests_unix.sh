#!/bin/sh
test_files=""
test_files="$test_files test/keyvault/test_serialization.py:TestSerialization"
test_files="$test_files test/keyvault/test_signature.py:TestSignatures"
test_files="$test_files test/messaging/anonymization/test_community.py:TestTunnelCommunity"
test_files="$test_files test/messaging/anonymization/test_hiddenservices.py:TestHiddenServices"
export PYTHONPATH='.'
for f in $test_files; do
echo "======================================================================"
echo " $f"
echo "======================================================================"
nosetests -x -v "$f"
if [ $? -ne 0 ] ; then echo "CRITICAL FAILURE: ABORTING" ; break ; fi
done
echo "Tests completed!"
