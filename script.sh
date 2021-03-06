#!/bin/sh

ip=`ifconfig eth0|grep "inet addr:"|awk 'BEGIN{FS=":"}{print $2}'|egrep -o '^[0-9]+.[0-9]+.[0-9]+.[0-9]+'`

GetPID() { 
    PsUser=$1 
    PsName=$2 
    pid=`ps -u $PsUser|grep $PsName|grep -v grep|grep -v vi|grep -v dbx|grep -v tail|grep -v start|grep -v stop |sed -n 1p |awk '{print $1}'` 
    echo $pid 
}

GetSysCPU() { 
   CpuIdle=`vmstat 1 5 |sed -n '3,$p'|awk '{x = x + $15} END {print x/5}' |awk -F. '{print $1}'`
   CpuNum=`echo "100-$CpuIdle" | bc`
   echo $CpuNum 
}

ExecCommand() {
   nohup tcpdump -l -nn -t -q "udp and dst host $ip"|./analysis 2 2>&1 &
}

cpu=`GetSysCPU`
PID=`GetPID root tcpdump`
echo "This ip is $ip"
echo "The process id is $PID"
echo "The system cpu is $cpu"

while true 
do {
#  to see whether the process exist
   PID=`GetPID root tcpdump`
   if [ -z $PID ] 
   then { 
        ExecCommand &
	PID=`GetPID root tcpdump`
   }
   fi
   
   if [ $PID -gt 0 ] 
   then {
  	 cpu=`GetSysCPU`
   	 if [ $cpu -gt 2 ] 
   	 then {
	 	
	 	echo "too high"
   	 	kill -stop $PID
   	 } else {
	 	echo $cpu
	 	echo "is ok"
   		kill -cont $PID
   	 }
   	 fi
   }
   fi
   sleep 5
}
done
