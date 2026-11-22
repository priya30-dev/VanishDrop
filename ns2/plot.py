"""Draws the NS2 result graphs from results/summary.csv and results/*_4_series.csv.

Usage:  python3 plot.py        (needs:  pip install matplotlib)
"""
import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
STYLE = {"Static": ("#E4572E", "o", "-"), "DV": ("#1F6BFF", "s", "--"), "LS": ("#17A398", "^", ":")}

rows = list(csv.DictReader(open(os.path.join(RES, "summary.csv"))))
for r in rows:
    for k, v in r.items():
        if k != "routing":
            r[k] = float(v)


def series(metric):
    out = {}
    for r in rows:
        out.setdefault(r["routing"], []).append((r["senders"], r[metric]))
    return out


def line_chart(metric, ylabel, title, fname):
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=150)
    for proto, pts in series(metric).items():
        color, marker, ls = STYLE[proto]
        xs, ys = zip(*sorted(pts))
        ax.plot(xs, ys, marker=marker, linestyle=ls, color=color, linewidth=2, label=f"{proto} routing")
    ax.set_xlabel("Number of simultaneous VanishDrop transfers across the backbone")
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left", fontsize=12, fontweight="bold")
    ax.set_xticks([1, 2, 4, 6])
    ax.grid(alpha=0.3)
    ax.legend(frameon=False)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(RES, fname))
    plt.close(fig)
    print("wrote", os.path.join("results", fname))


line_chart("per_flow_mbps", "Throughput per transfer (Mbps)", "Each transfer gets a smaller share of the 10 Mbps backbone", "throughput_per_flow.png")
line_chart("backbone_delay_ms", "Average end-to-end delay (ms)", "Delay grows as the router queue fills", "delay.png")
line_chart("tcp_loss_pct", "TCP packets dropped (%)", "Packet loss: queue overflow plus the 10 s link failure", "loss.png")

# Link failure: throughput over time with 4 transfers.
fig, ax = plt.subplots(figsize=(7, 4.2), dpi=150)
for proto in ("Static", "DV", "LS"):
    path = os.path.join(RES, f"{proto}_4_series.csv")
    if not os.path.exists(path):
        continue
    data = list(csv.DictReader(open(path)))
    color, _, ls = STYLE[proto]
    ax.plot([float(d["time_s"]) for d in data], [float(d["backbone_mbps"]) for d in data],
            color=color, linestyle=ls, linewidth=2, label=f"{proto} routing")
ax.axvspan(10, 20, color="#999999", alpha=0.15, label="r1–r2 link down")
ax.set_xlabel("Time (s)")
ax.set_ylabel("Data delivered across the backbone (Mbps)")
ax.set_title("Static routing stalls when the link fails; DV and LS reroute via r3", loc="left", fontsize=12, fontweight="bold")
ax.set_xlim(0, 30)
ax.grid(alpha=0.3)
ax.legend(frameon=False, loc="lower right")
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
fig.tight_layout()
fig.savefig(os.path.join(RES, "link_failure.png"))
plt.close(fig)
print("wrote", os.path.join("results", "link_failure.png"))
