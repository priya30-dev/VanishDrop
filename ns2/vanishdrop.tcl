# VanishDrop network model for NS2
#
# Usage:  ns vanishdrop.tcl <senders 1-6> <Static|DV|LS> <output-prefix> [nam]
#   e.g.  ns vanishdrop.tcl 4 DV results/DV_4
#         ns vanishdrop.tcl 4 DV demo nam      (also writes demo.nam for the animator)
#
# Topology (wired model of a hostel and a lab connected through campus routers):
#
#   hostel laptops h0..h5 ─┐                                ┌─ lab PCs l0..l5
#   nearby pair  nA, nB ───┤                                │
#                        sw1 ──100Mb── r1 ══10Mb══ r2 ──100Mb── sw2
#                                       \\         /
#                                        \\─ r3 ─/     backup path (higher cost)
#
# Traffic:
#   fid 1..6  VanishDrop link uploads/downloads: TCP NewReno + FTP, hostel -> lab (cross the backbone)
#   fid 50    Nearby send: TCP between two laptops on the same switch (never touches a router)
#   fid 100   Discovery beacons: small UDP packets (CBR), like VanishDrop's UDP broadcast
#
# Event: the main backbone link r1-r2 fails at 10 s and comes back at 20 s.
#   Static routing keeps sending into the dead link (packets dropped);
#   DV and LS find the backup path through r3.

if {$argc < 3} {
    puts "Usage: ns vanishdrop.tcl <senders 1-6> <Static|DV|LS> <output-prefix> \[nam\]"
    exit 1
}
set nsend  [lindex $argv 0]
set proto  [lindex $argv 1]
set out    [lindex $argv 2]
set usenam [expr {$argc > 3}]
if {$nsend < 1 || $nsend > 6} { puts "senders must be 1 to 6"; exit 1 }
if {[lsearch {Static DV LS} $proto] < 0} { puts "routing must be Static, DV or LS"; exit 1 }

set ns [new Simulator]
if {$proto ne "Static"} { $ns rtproto $proto }

set tf [open $out.tr w]
$ns trace-all $tf
if {$usenam} {
    set nf [open $out.nam w]
    $ns namtrace-all $nf
}
$ns color 1 Blue
$ns color 2 Red
$ns color 3 Green
$ns color 4 Orange
$ns color 5 Purple
$ns color 6 Brown
$ns color 50 DarkGreen
$ns color 100 Gray

# ---------------------------------------------------------------- nodes ---
for {set i 0} {$i < 6} {incr i} { set h($i) [$ns node] }
set nA  [$ns node]
set nB  [$ns node]
set sw1 [$ns node]
set r1  [$ns node]
set r2  [$ns node]
set r3  [$ns node]
set sw2 [$ns node]
for {set i 0} {$i < 6} {incr i} { set l($i) [$ns node] }

$sw1 label "hostel switch"
$sw2 label "lab switch"
$r1 label "router r1"
$r2 label "router r2"
$r3 label "router r3 (backup)"

# ---------------------------------------------------------------- links ---
for {set i 0} {$i < 6} {incr i} { $ns duplex-link $h($i) $sw1 100Mb 1ms DropTail }
$ns duplex-link $nA $sw1 100Mb 1ms DropTail
$ns duplex-link $nB $sw1 100Mb 1ms DropTail
$ns duplex-link $sw1 $r1 100Mb 2ms DropTail
$ns duplex-link $r1  $r2 10Mb 10ms DropTail
$ns duplex-link $r1  $r3 10Mb 15ms DropTail
$ns duplex-link $r3  $r2 10Mb 15ms DropTail
$ns duplex-link $r2 $sw2 100Mb 2ms DropTail
for {set i 0} {$i < 6} {incr i} { $ns duplex-link $l($i) $sw2 100Mb 1ms DropTail }

# The backbone is the bottleneck: give it a realistic router queue.
$ns queue-limit $r1 $r2 50
$ns queue-limit $r1 $r3 50
$ns queue-limit $r3 $r2 50

# Prefer the direct backbone: the backup path costs more.
$ns cost $r1 $r3 2
$ns cost $r3 $r1 2
$ns cost $r3 $r2 2
$ns cost $r2 $r3 2

$ns duplex-link-op $r1 $r2 orient right
$ns duplex-link-op $sw1 $r1 orient right
$ns duplex-link-op $r2 $sw2 orient right
$ns duplex-link-op $r1 $r3 orient right-down
$ns duplex-link-op $r3 $r2 orient right-up

# ---------------------------------------------------------------- flows ---
# VanishDrop transfers across the campus: TCP NewReno carrying FTP-style bulk data.
for {set i 0} {$i < $nsend} {incr i} {
    set tcp($i) [new Agent/TCP/Newreno]
    $tcp($i) set fid_ [expr {$i + 1}]
    $tcp($i) set packetSize_ 1460
    $tcp($i) set window_ 64
    $ns attach-agent $h($i) $tcp($i)
    set sink($i) [new Agent/TCPSink]
    $ns attach-agent $l($i) $sink($i)
    $ns connect $tcp($i) $sink($i)
    set ftp($i) [new Application/FTP]
    $ftp($i) attach-agent $tcp($i)
    $ns at [expr {1.0 + 0.2 * $i}] "$ftp($i) start"
    $ns at 28.0 "$ftp($i) stop"
}

# Nearby send: two laptops on the same switch.
set ntcp [new Agent/TCP/Newreno]
$ntcp set fid_ 50
$ntcp set packetSize_ 1460
$ntcp set window_ 64
$ns attach-agent $nA $ntcp
set nsink [new Agent/TCPSink]
$ns attach-agent $nB $nsink
$ns connect $ntcp $nsink
set nftp [new Application/FTP]
$nftp attach-agent $ntcp
$ns at 2.0 "$nftp start"
$ns at 28.0 "$nftp stop"

# Discovery beacons: small UDP datagrams, like VanishDrop's 3-second broadcast
# (sent every 0.5 s here so there are enough samples to measure delay).
set udp [new Agent/UDP]
$udp set fid_ 100
$ns attach-agent $h(0) $udp
set null [new Agent/Null]
$ns attach-agent $l(0) $null
$ns connect $udp $null
set cbr [new Application/Traffic/CBR]
$cbr set packetSize_ 120
$cbr set interval_ 0.5
$cbr attach-agent $udp
$ns at 0.5 "$cbr start"
$ns at 28.0 "$cbr stop"

# ------------------------------------------------------- link failure ---
$ns rtmodel-at 10.0 down $r1 $r2
$ns rtmodel-at 20.0 up   $r1 $r2

proc finish {} {
    global ns tf usenam nf
    $ns flush-trace
    close $tf
    if {$usenam} { close $nf }
    exit 0
}
$ns at 30.0 "finish"
$ns run
