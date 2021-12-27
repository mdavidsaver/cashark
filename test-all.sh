#!/bin/sh
set -e

IAM="$(readlink -f "$0")"
cd "$(dirname "$IAM")"

rm -f test/*.out

ret=0
for cap in test/*.*cap*
do
  echo "======================="
  echo " $cap"
  echo "======================="
  echo "::group::$(basename "$cap")"
  if ! tshark -r "$cap" -X lua_script:ca.lua -X lua_script:pva.lua -PO ca,pva 'ca || pva' > "$cap".out
  then
    echo "::error file=$(basename "$cap")::exit $?"
    ret=$?
  elif ! [ -s "$cap".out ]
  then
    echo "::error file=$(basename "$cap")::Empty output"
    ret=1
  fi
  echo "::endgroup::$(basename "$cap")"
done

exit $ret
