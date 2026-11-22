# Throughput (goodput) from an NS2 trace.
# Usage: awk -f throughput.awk results/DV_4.tr
#
# Counts TCP data bytes that reach their destination node:
#   'r' event, type tcp, and the receiving node ($4) equals the packet's destination node ($10).
# fid 50 is the Nearby (same switch) transfer; every other TCP fid crosses the backbone.

BEGIN { first = -1; last = 0 }
$1 == "r" && $5 == "tcp" {
    split($10, d, ".")
    if ($4 != d[1]) next
    if ($8 == 50) lan += $6
    else { wan += $6; flows[$8] = 1 }
    if (first < 0 || $2 < first) first = $2
    if ($2 > last) last = $2
}
END {
    span = 27.0   # flows run from about 1 s to 28 s
    n = 0; for (f in flows) n++
    printf "backbone_mbps=%.3f\nper_flow_mbps=%.3f\nnearby_mbps=%.3f\n", wan * 8 / span / 1e6, (n ? wan * 8 / span / 1e6 / n : 0), lan * 8 / 26.0 / 1e6
}
