# Backbone throughput over time, in 0.5-second steps (to see the 10 s link failure).
# Usage: awk -f timeseries.awk results/DV_4.tr > results/DV_4_series.csv

BEGIN { bin = 0.5 }
$1 == "r" && $5 == "tcp" && $8 != 50 {
    split($10, d, ".")
    if ($4 == d[1]) bytes[int($2 / bin)] += $6
}
END {
    print "time_s,backbone_mbps"
    for (i = 0; i < 60; i++) printf "%.1f,%.3f\n", i * bin, (bytes[i] * 8 / bin / 1e6)
}
