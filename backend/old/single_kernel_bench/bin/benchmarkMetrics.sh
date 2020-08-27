# benchmark metric sets with different numbers of cores.
# 11/19
echo "msetReplicaCtReplicaRate = {}"
for mSet in {1..5}
do
echo "msetReplicaCtReplicaRate[$mSet] = {}"
  for nReplicas in 1 2 4 8 16
  # for nReplicas in 1 2 4 6 8 10 12 14 16
  do
    # echo "#running"
    numactl --cpunodebind=0 --membind=0 ./starflow_app_benchmark -r $nReplicas -m $mSet
  done
done
