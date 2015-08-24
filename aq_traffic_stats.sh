#!/bin/sh


if [ "$#" -lt 1 ]
then {
  echo "params err!"
  echo "Usage     : sh aq_traffic_stats.sh 60 &"
  echo "60        : cpu occupancy rate limit"
  exit 0
}
fi

ip=`/sbin/ifconfig |grep "inet addr:"|grep -v "127.0.0.1"|awk 'BEGIN{FS=":"}{print $2}'|egrep -o '^[0-9]+.[0-9]+.[0-9]+.[0-9]+'`

GetTcpdumpPID() { 
    pid=`ps -ef|grep tcpdump|grep "udp and dst host"|grep -v grep|grep -v vi|grep -v dbx|grep -v tail|grep -v start|grep -v stop |sed -n 1p |awk '{print $2}'` 
    echo $pid 
}

GetSysCPU() { 
   CpuIdle=`vmstat 1 5 |sed -n '3,$p'|awk '{x = x + $15} END {print x/5}' |awk -F. '{print $1}'`
   #CpuIdle=`mpstat 1 1|grep Average|awk '{print int($10)}'`
   CpuNum=`echo "100-$CpuIdle" | bc`
   echo $CpuNum
}

ExecCommand() {
   nohup tcpdump -l -nn -t -q "udp and dst host $ip"|./analysis 2 2>&1 &
}

GetPID() { 
    PsUser=$1 
    PsName=$2
    pid=`ps -u $PsUser|grep $PsName|grep -v grep|grep -v vi|grep -v dbx|grep -v tail|grep -v start|grep -v stop |sed -n 1p |awk '{print $1}'` 
    echo $pid 
}

Exit() {
    TcpdumpPid=`GetTcpdumpPID`
    kill -9 $TcpdumpPid
    AnalysisPid=`GetPID root analysis`
    kill -9 $AnalysisPid
    exit 0
}

trap "Exit" INT QUIT
cpu=`GetSysCPU`
startTime=`date +%s`
echo "This ip is $ip"
echo "The current system cpu occupancy rate is $cpu"
echo "The process starts at $startTime"
echo "=================start running================="

while true 
do {
#  to see if it's time over
    endTime=`date +%s`
    interval=$(($endTime-$startTime))
    echo "interval is $interval"
    if [ $interval -gt 86400 ]
    then {
    	Exit		
    }
    fi
#  to see whether the process exist
    PID=`GetTcpdumpPID`
    #echo "TcpdumpPID is $PID"
    if [ -z $PID ] 
    then { 
        ExecCommand &
        PID=`GetTcpdumpPID`
        continue;
    }
    fi
   
    if [ $PID -gt 0 ] 
    then {
        cpu=`GetSysCPU`
        if [ $cpu -gt $1 ] 
        then {
            echo "too high,current cpu occupancy rate is $cpu > $1(the limit)"
            kill -stop $PID
        } 
        else {
            #echo "cpu occupancy rate is $cpu, ok"
            kill -cont $PID
        }
        fi
   }
   fi
   sleep 20
}
done
