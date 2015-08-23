#!/bin/sh

GetPID() { 
    PsUser=$1 
    PsName=$2
    pid=`ps -u $PsUser|grep $PsName|grep -v grep|grep -v vi|grep -v dbx|grep -v tail|grep -v start|grep -v stop |sed -n 1p |awk '{print $1}'` 
    echo $pid 
}

#GetPID root tcpdump
PID=`ps -u root|grep tcpdump|awk '{print $1}'`

echo $PID

if [ -z $PID ] 
then {
  echo "tcpdump didn't run"
} else {
  kill -9 $PID
}
fi
