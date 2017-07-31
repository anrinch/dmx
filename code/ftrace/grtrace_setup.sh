#!/bin/bash
#set -x

DBFS=/sys/kernel/debug
TRFS="$DBFS/tracing"

echo "Turning trace off..."
echo 0 > $TRFS/tracing_on

echo "Getting available filters..."
FUNC_FILTER=`cat $TRFS/available_filter_functions | grep dm_mintegrity | awk '{print $1}'`

echo "$FUNC_FILTER"

echo function_graph > $TRFS/current_tracer

for f in $FUNC_FILTER
do
	echo "Adding filter '$f'..."
	echo $f >>$TRFS/set_graph_function
	#echo $f >> $TRFS/set_ftrace_filter
done

echo "Checking current filter setting:"
cat $TRFS/set_ftrace_filter

echo "Re-enalbing trace..."
echo 1 > $TRFS/tracing_on

echo "done"
