# Module 4 · NS2 simulation

The `ns2/` folder models the network VanishDrop runs on and measures **throughput, delay and
packet loss** under three routing protocols, with a link failure in the middle.

## 1. How to run

NS2 doesn't run on Windows. Use either:
- **Your college lab PC** (Linux with NS2), or
- **GitHub Codespaces**: open the project in a codespace, then in its terminal:
  ```
  sudo apt-get update && sudo apt-get install -y ns2
  pip install matplotlib
  ```

Then:
```
cd ns2
sh run_all.sh        # 12 simulations (Static/DV/LS × 1, 2, 4, 6 transfers), about 2 minutes
python3 plot.py      # writes 4 graphs into ns2/results/
```
To watch the animation on a lab PC: `ns vanishdrop.tcl 4 DV demo nam` then `nam demo.nam`.
One run by hand: `ns vanishdrop.tcl 4 DV results/DV_4`, then
`awk -f throughput.awk results/DV_4.tr` (likewise `delay.awk`, `loss.awk`).

## 2. The model (`vanishdrop.tcl`)

```
hostel laptops h0–h5 ─┐                               ┌─ lab PCs l0–l5
nearby pair nA, nB ───┤                               │
                    sw1 ──100Mb 2ms── r1 ══10Mb 10ms══ r2 ──100Mb 2ms── sw2
                                       \                /
                                        └── r3 (backup, 10Mb 15ms + 15ms, cost 2)
access links: 100Mb 1ms · router queues: DropTail, 50 packets
```

| Traffic | NS2 agents | Stands for |
|---|---|---|
| fid 1–6 | TCP NewReno + FTP, h*i* → l*i*, 1460-byte packets | Link uploads/downloads crossing the campus |
| fid 50 | TCP NewReno + FTP, nA → nB (same switch) | Nearby send on the same Wi-Fi |
| fid 100 | UDP + CBR, 120-byte packets | Discovery beacons |

At **10 s the r1–r2 link fails**; at **20 s it comes back** (`rtmodel-at`).
Routing: `Static` (computed once), `DV` (distance vector, like RIP), `LS` (link state, like OSPF).

The AWK scripts read the classic trace format
(`event time from to type size flags fid src dst seq id`):
- **throughput.awk**: bytes of TCP packets received at their destination node ÷ time.
- **delay.awk**: for each packet id, time received at destination − time queued at source.
- **loss.awk**: packets sent − packets delivered. (Counting `d` lines isn't enough: under Static
  routing NS2 discards packets on a dead link without writing a `d` line.)

## 3. Results (from our run)

| Routing | Transfers | Throughput per transfer (Mbps) | Backbone total (Mbps) | Avg delay (ms) | Max delay (ms) | TCP loss % | UDP discovery loss % |
|---|---|---|---|---|---|---|---|
| Static | 1 | 5.10 | 5.10 | 56.0 | 60.9 | 0.025 | 37.0 |
| Static | 2 | 2.60 | 5.19 | 65.2 | 76.4 | 0.043 | 50.0 |
| Static | 4 | 1.32 | 5.27 | 67.5 | 76.4 | 0.072 | 51.9 |
| Static | 6 | 0.88 | 5.29 | 67.9 | 76.5 | 0.102 | 53.7 |
| DV | 1 | 9.24 | 9.24 | 53.9 | 60.9 | 0.019 | 0.0 |
| DV | 2 | 4.75 | 9.51 | 64.2 | 97.2 | 0.045 | 16.7 |
| DV | 4 | 2.43 | 9.72 | 67.5 | 97.2 | 0.077 | 16.7 |
| DV | 6 | 1.63 | 9.77 | 68.5 | 97.2 | 0.117 | 24.1 |
| LS | 1 | 9.24 | 9.24 | 53.9 | 60.9 | 0.019 | 0.0 |
| LS | 2 | 4.78 | 9.56 | 70.8 | 97.2 | 0.055 | 25.9 |
| LS | 4 | 2.43 | 9.74 | 67.4 | 97.2 | 0.075 | 22.2 |
| LS | 6 | 1.63 | 9.77 | 68.4 | 97.1 | 0.120 | 24.1 |

Nearby send (same switch): **99.9 Mbps**, **5.7 ms** average delay, in every run.

Graphs in `ns2/results/`: `throughput_per_flow.png`, `delay.png`, `loss.png`, `link_failure.png`.

## 4. What the results mean

1. **The backbone is the bottleneck.** Total throughput stays near 10 Mbps whatever the number
   of transfers, so each transfer gets roughly 10 ÷ n Mbps. TCP shares the link fairly.
2. **Delay rises with load.** More transfers fill the 50-packet router queue, adding queueing
   delay on top of the ~32 ms of propagation (1+2+10+2+1 ms each way plus ACKs).
3. **Static routing can't survive a failure.** From 10 s to about 22.5 s nothing crosses the
   backbone (see `link_failure.png`), so total throughput is about half. It recovers about 2.5 s
   *after* the link returns because TCP's retransmission timer had backed off exponentially.
   UDP has no such back-off, so 37–54% of discovery packets are simply lost.
4. **DV and LS reroute in about a second** through r3, keeping throughput near 10 Mbps. The
   maximum delay rises to ~97 ms because the backup path is longer (15 + 15 ms).
5. **DV vs LS:** near identical in this small network. Both converge in about a second; LS
   floods link-state updates, DV exchanges distance vectors with neighbours. In large networks
   LS converges faster and avoids DV's count-to-infinity problem.
6. **UDP loses more than TCP under load.** CBR doesn't slow down when the queue is full, so its
   packets get dropped at the bottleneck (16–26% with DV/LS), while TCP backs off and retransmits.
   This is why VanishDrop uses UDP only for discovery, where a lost beacon is harmless.
7. **Nearby send is 10× faster** (99.9 vs ≤ 9.2 Mbps) with a tenth of the delay, because both
   laptops are on the same switch: no router, no shared backbone. This is the case for sending
   directly over Wi-Fi instead of uploading to a server across the internet.
