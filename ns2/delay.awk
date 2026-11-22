# End-to-end delay from an NS2 trace.
# Usage: awk -f delay.awk results/DV_4.tr
#
# For each packet id: the time it entered the queue at its source node ('+' at node == source)
# and the time it was received at its destination node ('r' at node == destination).

$1 == "+" && ($5 == "tcp" || $5 == "cbr") {
    split($9, s, ".")
    if ($3 == s[1] && !($12 in start)) { start[$12] = $2; kind[$12] = ($5 == "cbr") ? "udp" : ($8 == 50 ? "lan" : "wan") }
}
$1 == "r" && ($5 == "tcp" || $5 == "cbr") {
    split($10, d, ".")
    if ($4 == d[1] && ($12 in start)) {
        k = kind[$12]; dl = $2 - start[$12]
        sum[k] += dl; cnt[k]++
        if (dl > max[k]) max[k] = dl
        delete start[$12]
    }
}
END {
    printf "backbone_delay_ms=%.2f\nbackbone_max_delay_ms=%.2f\n", (cnt["wan"] ? 1000 * sum["wan"] / cnt["wan"] : 0), 1000 * max["wan"]
    printf "nearby_delay_ms=%.2f\n", (cnt["lan"] ? 1000 * sum["lan"] / cnt["lan"] : 0)
    printf "discovery_delay_ms=%.2f\n", (cnt["udp"] ? 1000 * sum["udp"] / cnt["udp"] : 0)
}
