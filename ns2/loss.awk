# Packet loss from an NS2 trace.
# Usage: awk -f loss.awk results/DV_4.tr
#
# Loss = packets that left their source but never reached their destination.
#   sent:      '+' at the source node (first time we see that packet id)
#   delivered: 'r' at the destination node
# We don't just count 'd' (drop) lines: when a link is down under Static routing,
# NS2 discards packets without writing a 'd' line, so drop lines undercount.
# Packets sent in the last 0.5 s are ignored because they may still be in flight.

$1 == "+" && ($5 == "tcp" || $5 == "cbr") && $2 < 27.5 {
    split($9, s, ".")
    if ($3 == s[1] && !($12 in kind)) { kind[$12] = $5; sent[$5]++ }
}
$1 == "r" && ($5 == "tcp" || $5 == "cbr") {
    split($10, d, ".")
    if ($4 == d[1] && ($12 in kind) && !($12 in got)) { got[$12] = 1; recv[kind[$12]]++ }
}
END {
    lt = sent["tcp"] - recv["tcp"]; lu = sent["cbr"] - recv["cbr"]
    printf "tcp_sent=%d\ntcp_lost=%d\ntcp_loss_pct=%.3f\n", sent["tcp"], lt, (sent["tcp"] ? 100 * lt / sent["tcp"] : 0)
    printf "udp_sent=%d\nudp_lost=%d\nudp_loss_pct=%.3f\n", sent["cbr"], lu, (sent["cbr"] ? 100 * lu / sent["cbr"] : 0)
}
