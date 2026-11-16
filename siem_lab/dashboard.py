"""Generate a self-contained HTML report and a Grafana TestData snapshot."""

import csv
import json
from base64 import b64encode
from collections import Counter
from dataclasses import dataclass
from html import escape
from io import BytesIO, StringIO
from pathlib import Path
from typing import TypedDict, cast

import yaml
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator

from siem_lab.detect import REPO_ROOT, RULES
from siem_lab.records import CUSTOMERS, Severity, write_json

DEFAULT_DASHBOARD = REPO_ROOT / "config/dashboard.yml"
CHART_BACKGROUND = "#151e2c"
SEVERITY_COLORS = {"critical": "#fe798a", "high": "#f7a960", "medium": "#62cbe4", "low": "#97acbd"}

STYLE = """
:root{color-scheme:dark;font:16px system-ui,sans-serif;color:#f0f4fa;background:#101622}
*{box-sizing:border-box} body{margin:0}
main{max-width:1312px;margin:auto;padding:32px 34px 26px}
header{display:flex;gap:16px;align-items:center;justify-content:space-between;padding-bottom:19px;
border-bottom:1px solid #29384b;font-weight:700;letter-spacing:.015em}
.brand{display:flex;align-items:center;gap:11px}
.mark{display:grid;place-items:center;color:#8df1dd;background:#183932;border:1px solid #2e6559;
border-radius:9px;width:32px;height:32px;font:bold 17px monospace}
.scope{color:#afc5d1;font-size:13px;font-weight:500}
.intro{margin:22px 0 20px}
h1{font-size:clamp(32px,5vw,51px);line-height:1.04;letter-spacing:-.056em;margin:0 0 8px}
.intro p{color:#afc5d1;margin:0;font-size:14px;line-height:1.5}
.stats,.grid{display:grid;gap:12px}
.stats{grid-template-columns:repeat(3,1fr);margin-bottom:16px}
.card{border:1px solid #2b3c51;border-radius:12px;background:#151e2c}
.stat{padding:13px 17px}
.stat dt{color:#bdd0db;font-size:13px}
.stat dd{margin:4px 0 0;font-size:30px;font-weight:730;letter-spacing:-.04em;color:#95e7d8}
.grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.panel{padding:13px 12px 7px}
h2{font-size:15px;letter-spacing:.005em;margin:0 0 5px}
.panel h2{margin-left:5px}
.panel img{display:block;width:100%;height:auto}
.recent{margin-top:16px;padding:13px 17px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;text-align:left;white-space:nowrap}
th,td{padding:6px 10px 6px 0;border-bottom:1px solid #243347}
thead{color:#adc3d2} tbody tr:last-child td{border-bottom:0}
.severity{font-weight:750}
.critical{color:#fe99a5}.high{color:#ffc089}.medium{color:#80d9ed}.low{color:#b7cad8}
time,.ip{font:12px ui-monospace,monospace;color:#b8d2de}
footer{color:#afc5d1;font-size:12px;margin-top:14px}
@media(max-width:720px){main{padding:22px 15px}.grid{grid-template-columns:1fr}
.stat{padding:10px}.stat dd{font-size:23px}.scope{font-size:11px}}
"""


class AlertRow(TypedDict):
    severity: str
    customer: str
    rule_id: str
    title: str
    source_ip: str
    detected_at: str
    mitre_technique_id: str


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    title: str
    customers: dict[str, str]
    top_source_ips: int


@dataclass(frozen=True, slots=True)
class Panel:
    title: str
    field: str
    rows: list[tuple[str, int]]
    colors: list[str]


def load_config(path: Path) -> DashboardConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.keys() != {"title", "customers", "top_source_ips"}:
        raise ValueError("Dashboard config requires title, customers and top_source_ips")
    title, customers, top = raw["title"], raw["customers"], raw["top_source_ips"]
    if not isinstance(title, str) or not title.strip() or type(top) is not int or top < 1:
        raise ValueError("Dashboard title must be nonempty and top_source_ips must be positive")
    if (
        not isinstance(customers, dict)
        or customers.keys() != set(CUSTOMERS)
        or any(not isinstance(name, str) or not name.strip() for name in customers.values())
    ):
        raise ValueError("Dashboard config must name each fixture customer")
    return DashboardConfig(title, customers, top)


def read_alerts(path: Path) -> list[AlertRow]:
    items = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ValueError("Alerts must be a JSON array")
    for row in items:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(key), str) for key in AlertRow.__required_keys__
        ):
            raise ValueError("Each alert must contain the dashboard's string fields")
        if row["severity"] not in SEVERITY_COLORS or row["customer"] not in CUSTOMERS:
            raise ValueError("Unknown alert severity or customer")
        if row["rule_id"] not in {rule.id for rule in RULES}:
            raise ValueError("Unknown alert rule")
    return cast(list[AlertRow], items)


def panels(alerts: list[AlertRow], config: DashboardConfig) -> list[Panel]:
    severity = Counter(alert["severity"] for alert in alerts)
    customers = Counter(alert["customer"] for alert in alerts)
    rules = Counter(alert["rule_id"] for alert in alerts)
    ips = Counter(alert["source_ip"] for alert in alerts)
    top_ips = sorted(ips.items(), key=lambda row: (-row[1], row[0]))[: config.top_source_ips]
    return [
        Panel(
            "Alerts by severity",
            "Severity",
            [(level.title(), severity[level]) for level in Severity],
            [SEVERITY_COLORS[level] for level in Severity],
        ),
        Panel(
            "Alerts by customer",
            "Customer",
            [(config.customers[customer], customers[customer]) for customer in CUSTOMERS],
            ["#65d4bc"] * len(CUSTOMERS),
        ),
        Panel(
            "Alerts by rule",
            "Rule",
            [(rule.title, rules[rule.id]) for rule in RULES],
            ["#7ea9f2"] * len(RULES),
        ),
        Panel("Top source IPs", "Source IP", top_ips, ["#b7a1fd"] * len(top_ips)),
    ]


def chart_image(panel: Panel) -> str:
    figure = Figure(figsize=(6.2, 1.75), dpi=160, facecolor=CHART_BACKGROUND)
    axis = figure.subplots()
    figure.subplots_adjust(left=0.27, right=0.95, top=0.97, bottom=0.18)
    axis.set_facecolor(CHART_BACKGROUND)
    for spine in axis.spines.values():
        spine.set_visible(False)
    if panel.rows:
        labels, counts = zip(*panel.rows, strict=True)
        bars = axis.barh(labels, counts, color=panel.colors, height=0.48, zorder=3)
        axis.bar_label(bars, padding=4, color="#e7f2fb", fontsize=8)
        axis.invert_yaxis()
        axis.set_xlim(0, max(1, max(counts)) * 1.23)
        axis.xaxis.set_major_locator(MaxNLocator(integer=True))
        axis.grid(axis="x", color="#29394d", linewidth=0.6)
        axis.tick_params(axis="both", length=0, colors="#c2d3df", labelsize=8)
    else:
        axis.set_axis_off()
        axis.text(0.5, 0.5, "No alerts in this replay", color="#c2d3df", ha="center", va="center")
    encoded = BytesIO()
    FigureCanvasAgg(figure).print_png(encoded)
    return b64encode(encoded.getvalue()).decode("ascii")


def grafana_model(groups: list[Panel], config: DashboardConfig) -> dict:
    """Embed alert aggregates in Grafana's built-in TestData CSV query format."""
    datasource = {"type": "grafana-testdata-datasource", "uid": "${DS_TESTDATA}"}
    items = []
    for index, panel in enumerate(groups):
        csv_data = StringIO(newline="")
        writer = csv.writer(csv_data, lineterminator="\n")
        writer.writerow((panel.field, "Alerts"))
        writer.writerows(panel.rows)
        items.append(
            {
                "id": index + 1,
                "title": panel.title,
                "type": "table",
                "datasource": datasource,
                "gridPos": {"x": index % 2 * 12, "y": index // 2 * 8, "w": 12, "h": 8},
                "targets": [
                    {
                        "refId": "A",
                        "datasource": datasource,
                        "scenarioId": "csv_content",
                        "csvContent": csv_data.getvalue(),
                    }
                ],
            }
        )
    return {
        "title": f"{config.title} — alert snapshot",
        "uid": "siem-alerting-lab",
        "schemaVersion": 39,
        "version": 1,
        "tags": ["synthetic", "siem-lab"],
        "timezone": "utc",
        "__inputs": [
            {
                "name": "DS_TESTDATA",
                "label": "TestData",
                "type": "datasource",
                "pluginId": "grafana-testdata-datasource",
                "pluginName": "TestData",
            }
        ],
        "panels": items,
    }


def html_dashboard(alerts: list[AlertRow], groups: list[Panel], config: DashboardConfig) -> str:
    cards = []
    for group in groups:
        alt = escape(", ".join(f"{label} {count}" for label, count in group.rows) or "No alerts")
        cards.append(
            f'<section class="card panel"><h2>{escape(group.title)}</h2>'
            f'<img alt="{alt}" src="data:image/png;base64,{chart_image(group)}"></section>'
        )
    rows = []
    for alert in sorted(alerts, key=lambda item: item["detected_at"], reverse=True)[:8]:
        level = escape(alert["severity"])
        stamp = escape(alert["detected_at"])
        rows.append(
            f'<tr><td><time datetime="{stamp}">{stamp.replace("T", " ")}</time></td>'
            f'<td class="severity {level}">{level.title()}</td>'
            f"<td>{escape(config.customers[alert['customer']])}</td><td>{escape(alert['title'])}</td>"
            f'<td class="ip">{escape(alert["source_ip"])}</td>'
            f"<td>{escape(alert['mitre_technique_id'])}</td></tr>"
        )
    recent = "".join(rows) or '<tr><td colspan="6">No alerts in this replay.</td></tr>'
    title = escape(config.title)
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} | Alert overview</title><style>{STYLE}</style></head>
<body><main>
<header><div class="brand"><span class="mark" aria-hidden="true">∿</span>{title}</div>
<span class="scope">Synthetic telemetry · UTC</span></header>
<section class="intro"><h1>Alert overview</h1><p>Customer detections from a replay of authentication,
web, and firewall logs.</p></section>
<dl class="stats">
<div class="card stat"><dt>Alerts</dt><dd>{len(alerts)}</dd></div>
<div class="card stat"><dt>Customer environments</dt><dd>{len(config.customers)}</dd></div>
<div class="card stat"><dt>Rules fired</dt><dd>{len({row["rule_id"] for row in alerts})}</dd></div>
</dl>
<div class="grid">{"".join(cards)}</div>
<section class="card recent"><h2>Recent alerts</h2><table>
<thead><tr><th>Detected at</th><th>Severity</th><th>Customer</th><th>Rule</th>
<th>Source IP</th><th>ATT&amp;CK</th></tr></thead><tbody>{recent}</tbody></table></section>
<footer>Generated from the lab's alert JSON. All events and customer names are fictional.</footer>
</main></body></html>
"""


def render(alert_file: Path, destination: Path, config_path: Path = DEFAULT_DASHBOARD) -> None:
    """Render both dashboard formats directly from the recorded alerts."""
    alerts = read_alerts(alert_file)
    config = load_config(config_path)
    groups = panels(alerts, config)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "dashboard.html").write_text(
        html_dashboard(alerts, groups, config), encoding="utf-8", newline="\n"
    )
    write_json(destination / "grafana-dashboard.json", grafana_model(groups, config))
