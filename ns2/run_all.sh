#!/bin/sh
# Runs every experiment, analyses each trace with the AWK scripts, and writes results/summary.csv.
# Usage:  sh run_all.sh          (set KEEP=1 to keep the large .tr trace files)
set -e
cd "$(dirname "$0")"
mkdir -p results
echo "routing,senders,backbone_mbps,per_flow_mbps,nearby_mbps,backbone_delay_ms,backbone_max_delay_ms,nearby_delay_ms,discovery_delay_ms,tcp_sent,tcp_lost,tcp_loss_pct,udp_sent,udp_lost,udp_loss_pct" > results/summary.csv

for proto in Static DV LS; do
  for n in 1 2 4 6; do
    name="results/${proto}_${n}"
    echo "Running $proto routing with $n senders..."
    ns vanishdrop.tcl "$n" "$proto" "$name" > /dev/null 2>&1
    vals=$( { awk -f throughput.awk "$name.tr"; awk -f delay.awk "$name.tr"; awk -f loss.awk "$name.tr"; } | cut -d= -f2 | paste -sd, - )
    echo "$proto,$n,$vals" >> results/summary.csv
    if [ "$n" = "4" ]; then awk -f timeseries.awk "$name.tr" > "results/${proto}_4_series.csv"; fi
    if [ -z "$KEEP" ]; then rm -f "$name.tr"; fi
  done
done

echo
echo "Done. Results in results/summary.csv"
echo "Make the graphs with:  python3 plot.py"
