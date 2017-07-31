#!/bin/bash
#set -x

DBFS=/sys/kernel/debug
TRFS="$DBFS/tracing"

DATE=`date +%Y%m%d-%H%m%s`

FLIST="funcs.list"

echo "Turning trace off..."
echo 0 > $TRFS/tracing_on

echo "Getting available filters..."
FUNC_FILTER=`cat $FLIST`

echo "$FUNC_FILTER"

echo function_graph > $TRFS/current_tracer

for f in $FUNC_FILTER
do
	echo "Adding filter '$f'..."
	echo $f >>$TRFS/set_graph_function
	#echo $f >> $TRFS/set_ftrace_filter
done

echo "Checking current filter setting:"
cat $TRFS/set_graph_function

echo "Re-enalbing trace..."
echo 1 > $TRFS/tracing_on

echo "done"

echo "Gathering trace data"

cat $TRFS/trace_pipe > trace_${DATE}.log
