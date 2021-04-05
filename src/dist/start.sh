#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

pcount=`ps -ef | grep -v grep | grep dispatch | grep -v spring.log | wc -l`

if [ $pcount -gt 0 ]
then
    echo "当前运行数量$pcount"
    echo "dispatch程序已经在运行"
else
    echo "开始第一次运行....."
    echo "休眠30s,等待第一次启动执行..."
    sleep 30

    nohup java -jar $DIR/dispatch-0.0.1-SNAPSHOT.jar > /dev/null 2>&1 &
fi

echo "只有在输入两参数(参数一为目标addr,参数二为区域id) 时，才会主动定时发数据，直到kill改进程"

if [ $# -eq 2 ]
then 
    cmd="http://localhost:10089/api/v1/dispatch?addr=$1&areaId=$2"
    echo "$cmd"
    curl $cmd
fi

