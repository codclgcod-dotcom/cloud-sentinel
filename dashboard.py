from flask import Flask, render_template_string
import sqlite3
import json
import html

app = Flask(__name__)

DATABASE = "security_alerts.db"


def get_alerts():
    connection = sqlite3.connect(DATABASE)

    alerts = connection.execute("""
        SELECT event_name, username, source_ip,
               severity, reason, event_time
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return alerts
@app.route("/robots.txt")
def robots():
    return """User-agent: *
Allow: /
"""
@app.route("/sitemap.xml")
def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://cloud-sentinel-8f8u.onrender.com/</loc>
    </url>
</urlset>
"""

@app.route("/")
def dashboard():

    alerts = get_alerts()

    total = len(alerts)

    critical = sum(1 for a in alerts if a[3] == "CRITICAL")
    high = sum(1 for a in alerts if a[3] == "HIGH")
    medium = sum(1 for a in alerts if a[3] == "MEDIUM")
    low = sum(1 for a in alerts if a[3] == "LOW")

    # -----------------------------------------
    # Alert activity over time
    # -----------------------------------------

    time_counts = {}

    for alert in alerts:

        event_time = alert[5]

        if event_time:
            label = event_time[:13]
            time_counts[label] = time_counts.get(label, 0) + 1

    sorted_times = sorted(time_counts.keys())

    time_labels = json.dumps(sorted_times)
    time_values = json.dumps(
        [time_counts[t] for t in sorted_times]
    )

    # -----------------------------------------
    # Alert table
    # -----------------------------------------

    rows = ""

    for alert in alerts:

        event_name = html.escape(str(alert[0] or "Unknown"))
        username = html.escape(str(alert[1] or "Unknown"))
        source_ip = html.escape(str(alert[2] or "Unknown"))
        severity = html.escape(str(alert[3] or "LOW"))
        reason = html.escape(str(alert[4] or ""))
        event_time = html.escape(str(alert[5] or ""))

        rows += f"""
        <tr class="alert-row"
            data-severity="{severity}"
            onclick="showAlert(
                '{event_name}',
                '{username}',
                '{source_ip}',
                '{severity}',
                '{reason}',
                '{event_time}'
            )">

            <td>
                <div class="event-cell">

                    <div class="event-icon">
                        <span>⚡</span>
                    </div>

                    <div>
                        <div class="event-name">
                            {event_name}
                        </div>

                        <div class="event-type">
                            CLOUD SECURITY EVENT
                        </div>
                    </div>

                </div>
            </td>

            <td>
                <span class="user-name">
                    {username}
                </span>
            </td>

            <td>
                <span class="ip-address">
                    {source_ip}
                </span>
            </td>

            <td>
                <span class="severity-badge {severity}">
                    <span class="severity-dot"></span>
                    {severity}
                </span>
            </td>

            <td>
                <span class="reason-text">
                    {reason}
                </span>
            </td>

            <td>
                <span class="time-text">
                    {event_time}
                </span>
            </td>

        </tr>
        """

    if not rows:

        rows = """
        <tr>
            <td colspan="6">
                <div class="empty-state">
                    <div class="empty-icon">✓</div>
                    <h3>No Security Alerts</h3>
                    <p>
                        Your monitoring system has not detected
                        any suspicious activity.
                    </p>
                </div>
            </td>
        </tr>
        """

    return render_template_string(
        PAGE,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        time_labels=time_labels,
        time_values=time_values,
        rows=rows
    )


PAGE = """
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<meta http-equiv="refresh" content="30">

<title>Cloud Sentinel | Security Operations Center</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<link rel="preconnect"
      href="https://fonts.googleapis.com">

<link rel="preconnect"
      href="https://fonts.gstatic.com"
      crossorigin>

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
      rel="stylesheet">


<style>

/* =====================================================
   GLOBAL
===================================================== */

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {

    margin: 0;

    font-family: "Inter", Arial, sans-serif;

    background:
        radial-gradient(
            circle at 80% 0%,
            rgba(37, 99, 235, 0.14),
            transparent 28%
        ),
        radial-gradient(
            circle at 15% 30%,
            rgba(6, 182, 212, 0.06),
            transparent 25%
        ),
        #070b14;

    color: #e5e7eb;

    min-height: 100vh;
}


/* =====================================================
   SCROLLBAR
===================================================== */

::-webkit-scrollbar {
    width: 7px;
}

::-webkit-scrollbar-track {
    background: #080d18;
}

::-webkit-scrollbar-thumb {
    background: #263449;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #3b82f6;
}


/* =====================================================
   SIDEBAR
===================================================== */

.sidebar {

    position: fixed;

    left: 0;
    top: 0;
    bottom: 0;

    width: 250px;

    background:
        linear-gradient(
            180deg,
            #0b1220 0%,
            #080e19 100%
        );

    border-right: 1px solid #1b2739;

    padding: 22px 15px;

    z-index: 100;
}


.logo {

    display: flex;

    align-items: center;

    gap: 12px;

    padding: 8px 12px 30px;
}


.logo-icon {

    width: 43px;
    height: 43px;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #06b6d4
        );

    display: flex;

    align-items: center;
    justify-content: center;

    font-size: 21px;

    box-shadow:
        0 8px 30px
        rgba(37, 99, 235, .35);
}


.logo-title {

    color: white;

    font-size: 16px;

    font-weight: 800;

    letter-spacing: -.3px;
}


.logo-subtitle {

    color: #64748b;

    font-size: 9px;

    margin-top: 3px;

    letter-spacing: 1.5px;

    font-weight: 600;
}


.nav-title {

    color: #475569;

    font-size: 9px;

    font-weight: 800;

    letter-spacing: 1.5px;

    padding: 12px;

    text-transform: uppercase;
}


.nav-item {

    display: flex;

    align-items: center;

    gap: 12px;

    padding: 12px 13px;

    margin: 4px 0;

    border-radius: 8px;

    color: #8794a8;

    font-size: 12px;

    font-weight: 600;

    cursor: pointer;

    transition: all .2s ease;

    border-left: 3px solid transparent;
}


.nav-item:hover {

    background: #121c2d;

    color: white;

    transform: translateX(2px);
}


.nav-item.active {

    background:
        linear-gradient(
            90deg,
            rgba(37, 99, 235, .18),
            rgba(6, 182, 212, .05)
        );

    color: #38bdf8;

    border-left-color: #38bdf8;
}


.nav-icon {

    width: 22px;

    text-align: center;

    font-size: 15px;
}


.sidebar-bottom {

    position: absolute;

    bottom: 20px;

    left: 15px;
    right: 15px;

    padding: 13px;

    border-radius: 10px;

    background: #0d1727;

    border: 1px solid #1c2a3f;
}


.system-mini {

    display: flex;

    align-items: center;

    gap: 9px;

    font-size: 10px;

    color: #94a3b8;
}


.online-dot {

    width: 8px;
    height: 8px;

    border-radius: 50%;

    background: #22c55e;

    box-shadow:
        0 0 12px
        rgba(34, 197, 94, .9);

    animation: pulse 2s infinite;
}


@keyframes pulse {

    0%,100% {
        opacity: 1;
    }

    50% {
        opacity: .45;
    }
}


/* =====================================================
   MAIN
===================================================== */

.main {

    margin-left: 250px;

    min-height: 100vh;
}


/* =====================================================
   TOPBAR
===================================================== */

.topbar {

    height: 72px;

    position: sticky;

    top: 0;

    z-index: 50;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 0 32px;

    background:
        rgba(7, 11, 20, .86);

    backdrop-filter: blur(16px);

    border-bottom: 1px solid #1b2739;
}


.page-title h1 {

    margin: 0;

    color: white;

    font-size: 17px;

    font-weight: 700;
}


.page-title p {

    margin: 4px 0 0;

    color: #64748b;

    font-size: 10px;
}


.top-actions {

    display: flex;

    align-items: center;

    gap: 15px;
}


.refresh-text {

    color: #64748b;

    font-size: 10px;
}


.status-pill {

    display: flex;

    align-items: center;

    gap: 8px;

    padding: 8px 12px;

    border-radius: 20px;

    background:
        rgba(34, 197, 94, .07);

    border: 1px solid
        rgba(34, 197, 94, .2);

    color: #4ade80;

    font-size: 10px;

    font-weight: 700;
}


.status-dot {

    width: 7px;
    height: 7px;

    border-radius: 50%;

    background: #22c55e;
}


/* =====================================================
   CONTENT
===================================================== */

.content {

    padding: 30px 32px 50px;

    max-width: 1700px;

    margin: auto;
}


/* =====================================================
   WELCOME
===================================================== */

.welcome {

    margin-bottom: 25px;
}


.welcome h2 {

    margin: 0;

    color: white;

    font-size: 25px;

    font-weight: 750;

    letter-spacing: -.5px;
}


.welcome p {

    margin: 7px 0 0;

    color: #64748b;

    font-size: 11px;
}


/* =====================================================
   KPI
===================================================== */

.stats-grid {

    display: grid;

    grid-template-columns:
        repeat(5, 1fr);

    gap: 14px;

    margin-bottom: 22px;
}


.stat-card {

    position: relative;

    overflow: hidden;

    padding: 19px;

    border-radius: 13px;

    background:
        linear-gradient(
            145deg,
            #0d1727,
            #0b1322
        );

    border: 1px solid #1b293d;

    transition: .25s ease;
}


.stat-card:hover {

    transform: translateY(-3px);

    border-color: #334155;

    box-shadow:
        0 15px 35px
        rgba(0,0,0,.2);
}


.stat-card::after {

    content: "";

    position: absolute;

    width: 90px;
    height: 90px;

    right: -40px;
    top: -40px;

    border-radius: 50%;

    opacity: .08;
}


.total::after {
    background: #38bdf8;
}

.critical::after {
    background: #ef4444;
}

.high::after {
    background: #f97316;
}

.medium::after {
    background: #facc15;
}

.low::after {
    background: #22c55e;
}


.stat-top {

    display: flex;

    align-items: center;

    justify-content: space-between;
}


.stat-label {

    color: #64748b;

    font-size: 9px;

    font-weight: 800;

    letter-spacing: 1px;

    text-transform: uppercase;
}


.stat-icon {

    width: 30px;
    height: 30px;

    border-radius: 8px;

    display: flex;

    align-items: center;
    justify-content: center;

    font-size: 13px;

    font-weight: 700;
}


.total .stat-icon {
    color: #38bdf8;
    background: rgba(56,189,248,.1);
}

.critical .stat-icon {
    color: #ef4444;
    background: rgba(239,68,68,.1);
}

.high .stat-icon {
    color: #f97316;
    background: rgba(249,115,22,.1);
}

.medium .stat-icon {
    color: #facc15;
    background: rgba(250,204,21,.1);
}

.low .stat-icon {
    color: #22c55e;
    background: rgba(34,197,94,.1);
}


.stat-number {

    margin-top: 12px;

    color: white;

    font-size: 30px;

    line-height: 1;

    font-weight: 800;
}


.stat-description {

    margin-top: 7px;

    color: #475569;

    font-size: 9px;
}


/* =====================================================
   ANALYTICS
===================================================== */

.analytics-grid {

    display: grid;

    grid-template-columns:
        .75fr 1.4fr;

    gap: 17px;

    margin-bottom: 22px;
}


.panel {

    background:
        linear-gradient(
            145deg,
            #0d1727,
            #0a1220
        );

    border: 1px solid #1b293d;

    border-radius: 13px;

    padding: 19px;
}


.panel-header {

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 15px;
}


.panel-title {

    color: white;

    font-size: 12px;

    font-weight: 700;
}


.panel-subtitle {

    margin-top: 4px;

    color: #526176;

    font-size: 9px;
}


.chart-box {

    height: 245px;

    position: relative;
}


/* =====================================================
   ALERT PANEL
===================================================== */

.alert-panel {

    background:
        linear-gradient(
            145deg,
            #0d1727,
            #0a1220
        );

    border: 1px solid #1b293d;

    border-radius: 13px;

    overflow: hidden;
}


.alert-header {

    padding: 19px 20px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    border-bottom: 1px solid #1b293d;
}


.alert-title h2 {

    margin: 0;

    color: white;

    font-size: 14px;
}


.alert-title p {

    margin: 5px 0 0;

    color: #526176;

    font-size: 9px;
}


.alert-count {

    padding: 6px 10px;

    border-radius: 6px;

    color: #94a3b8;

    background: #111c2d;

    border: 1px solid #1d2a3d;

    font-size: 9px;

    font-weight: 600;
}


/* =====================================================
   FILTER BAR
===================================================== */

.filter-bar {

    padding: 14px 20px;

    display: flex;

    align-items: center;

    gap: 9px;

    border-bottom: 1px solid #1b293d;
}


.search-wrapper {

    position: relative;

    flex: 1;

    max-width: 550px;
}


.search-icon {

    position: absolute;

    left: 12px;

    top: 50%;

    transform: translateY(-50%);

    color: #526176;

    font-size: 12px;
}


.search-input {

    width: 100%;

    padding: 10px 12px 10px 34px;

    border-radius: 7px;

    border: 1px solid #263449;

    background: #080f1c;

    color: #e2e8f0;

    outline: none;

    font-family: inherit;

    font-size: 10px;

    transition: .2s;
}


.search-input:focus {

    border-color: #2563eb;

    box-shadow:
        0 0 0 2px
        rgba(37,99,235,.1);
}


.severity-select {

    padding: 10px 28px 10px 11px;

    border-radius: 7px;

    border: 1px solid #263449;

    background: #080f1c;

    color: #cbd5e1;

    outline: none;

    font-family: inherit;

    font-size: 10px;

    cursor: pointer;
}


.clear-button {

    padding: 10px 13px;

    border-radius: 7px;

    border: 1px solid #263449;

    background: #111c2d;

    color: #94a3b8;

    font-family: inherit;

    font-size: 10px;

    cursor: pointer;

    transition: .2s;
}


.clear-button:hover {

    color: white;

    background: #1c2a3f;
}


/* =====================================================
   TABLE
===================================================== */

.table-container {

    overflow-x: auto;
}


table {

    width: 100%;

    min-width: 950px;

    border-collapse: collapse;
}


th {

    padding: 12px 20px;

    text-align: left;

    color: #526176;

    background: #09111e;

    font-size: 8px;

    font-weight: 800;

    letter-spacing: 1px;

    text-transform: uppercase;
}


td {

    padding: 14px 20px;

    border-top: 1px solid #162235;

    color: #cbd5e1;

    font-size: 10px;
}


.alert-row {

    cursor: pointer;

    transition: .15s;
}


.alert-row:hover {

    background:
        rgba(37,99,235,.055);
}


.event-cell {

    display: flex;

    align-items: center;

    gap: 10px;
}


.event-icon {

    width: 32px;
    height: 32px;

    border-radius: 8px;

    background:
        rgba(56,189,248,.07);

    border: 1px solid
        rgba(56,189,248,.1);

    display: flex;

    align-items: center;
    justify-content: center;

    color: #38bdf8;
}


.event-name {

    color: #e2e8f0;

    font-weight: 650;
}


.event-type {

    margin-top: 3px;

    color: #475569;

    font-size: 7px;

    letter-spacing: .8px;
}


.user-name {

    color: #cbd5e1;

    font-weight: 500;
}


.ip-address {

    color: #64748b;

    font-family: monospace;

    font-size: 9px;
}


.reason-text {

    display: block;

    max-width: 280px;

    overflow: hidden;

    text-overflow: ellipsis;

    white-space: nowrap;

    color: #94a3b8;
}


.time-text {

    color: #64748b;

    white-space: nowrap;

    font-size: 9px;
}


/* =====================================================
   SEVERITY
===================================================== */

.severity-badge {

    display: inline-flex;

    align-items: center;

    gap: 6px;

    padding: 5px 8px;

    border-radius: 5px;

    font-size: 8px;

    font-weight: 800;

    letter-spacing: .5px;
}


.severity-dot {

    width: 5px;
    height: 5px;

    border-radius: 50%;
}


.CRITICAL {

    color: #f87171;

    background: rgba(239,68,68,.1);
}

.CRITICAL .severity-dot {

    background: #ef4444;

    box-shadow: 0 0 7px #ef4444;
}


.HIGH {

    color: #fb923c;

    background: rgba(249,115,22,.1);
}

.HIGH .severity-dot {

    background: #f97316;
}


.MEDIUM {

    color: #facc15;

    background: rgba(250,204,21,.1);
}

.MEDIUM .severity-dot {

    background: #facc15;
}


.LOW {

    color: #4ade80;

    background: rgba(34,197,94,.1);
}

.LOW .severity-dot {

    background: #22c55e;
}


/* =====================================================
   EMPTY
===================================================== */

.empty-state {

    text-align: center;

    padding: 65px 20px;
}


.empty-icon {

    width: 48px;
    height: 48px;

    margin: auto;

    border-radius: 50%;

    display: flex;

    align-items: center;
    justify-content: center;

    background: rgba(34,197,94,.08);

    border: 1px solid
        rgba(34,197,94,.15);

    color: #22c55e;

    font-size: 20px;
}


.empty-state h3 {

    margin: 15px 0 5px;

    color: #cbd5e1;

    font-size: 13px;
}


.empty-state p {

    margin: 0;

    color: #475569;

    font-size: 9px;
}


/* =====================================================
   DEVELOPMENT TEAM
===================================================== */

.team-section {

    margin-top: 22px;

    padding: 24px;

    border-radius: 13px;

    background:
        linear-gradient(
            145deg,
            #0d1727,
            #0a1220
        );

    border: 1px solid #1b293d;
}


.team-header {

    text-align: center;

    margin-bottom: 20px;
}


.team-header h2 {

    margin: 0;

    color: white;

    font-size: 16px;

    font-weight: 750;
}


.team-header p {

    margin: 6px 0 0;

    color: #526176;

    font-size: 9px;
}


.team-grid {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 13px;
}


.team-card {

    padding: 18px 12px;

    text-align: center;

    border-radius: 11px;

    background: #091321;

    border: 1px solid #1b293d;

    transition: .25s ease;
}


.team-card:hover {

    transform: translateY(-3px);

    border-color: #2563eb;

    background: #0c1728;

    box-shadow:
        0 12px 30px
        rgba(37,99,235,.12);
}


.team-avatar {

    width: 50px;
    height: 50px;

    margin: 0 auto 12px;

    border-radius: 50%;

    display: flex;

    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #06b6d4
        );

    color: white;

    font-size: 14px;

    font-weight: 800;

    box-shadow:
        0 7px 20px
        rgba(37,99,235,.25);
}


.team-name {

    color: #e2e8f0;

    font-size: 11px;

    font-weight: 700;
}


.team-role {

    margin-top: 5px;

    color: #526176;

    font-size: 8px;

    letter-spacing: .4px;
}


/* =====================================================
   FOOTER
===================================================== */

.footer {

    padding: 20px 30px 30px;

    text-align: center;

    color: #334155;

    font-size: 8px;

    letter-spacing: .4px;
}


/* =====================================================
   RESPONSIVE
===================================================== */

@media (max-width: 1150px) {

    .stats-grid {
        grid-template-columns:
            repeat(3, 1fr);
    }

    .analytics-grid {
        grid-template-columns: 1fr;
    }

    .team-grid {
        grid-template-columns:
            repeat(2, 1fr);
    }
}


@media (max-width: 750px) {

    .sidebar {

        width: 65px;

        padding: 15px 8px;
    }

    .logo-title,
    .logo-subtitle,
    .nav-title,
    .nav-item span,
    .sidebar-bottom {

        display: none;
    }

    .logo {

        justify-content: center;

        padding: 8px 0 25px;
    }

    .nav-item {

        justify-content: center;

        padding: 12px 0;
    }

    .main {

        margin-left: 65px;
    }

    .content {

        padding: 20px 14px;
    }

    .topbar {

        padding: 0 14px;
    }

    .stats-grid {

        grid-template-columns:
            repeat(2, 1fr);
    }

    .refresh-text {

        display: none;
    }

    .filter-bar {

        flex-direction: column;

        align-items: stretch;
    }

    .search-wrapper {

        max-width: none;
    }

    .team-grid {

        grid-template-columns: 1fr;
    }
}


@media (max-width: 450px) {

    .stats-grid {

        grid-template-columns: 1fr;
    }

    .status-pill span {

        display: none;
    }

    .detail-grid {

        grid-template-columns: 1fr;
    }

    .detail-reason {

        grid-column: auto;
    }
}

</style>

</head>


<body>


<!-- =====================================================
     SIDEBAR
===================================================== -->

<aside class="sidebar">

    <div class="logo">

        <div class="logo-icon">
            🛡
        </div>

        <div>

            <div class="logo-title">
                Cloud Sentinel
            </div>

            <div class="logo-subtitle">
                SECURITY MONITOR
            </div>

        </div>

    </div>


    <div class="nav-title">
        Monitoring
    </div>


    <div class="nav-item active">

        <div class="nav-icon">
            ◈
        </div>

        <span>
            Overview
        </span>

    </div>


    <div class="nav-item"
         onclick="scrollToAlerts()">

        <div class="nav-icon">
            ⚠
        </div>

        <span>
            Security Alerts
        </span>

    </div>


    <div class="nav-item"
         onclick="scrollToAnalytics()">

        <div class="nav-icon">
            ◉
        </div>

        <span>
            Analytics
        </span>

    </div>


    <div class="nav-item"
         onclick="window.location.reload()">

        <div class="nav-icon">
            ≋
        </div>

        <span>
            Event Logs
        </span>

    </div>


    <div class="nav-title">
        System
    </div>


    <div class="nav-item">

        <div class="nav-icon">
            ⚙
        </div>

        <span>
            Configuration
        </span>

    </div>


    <div class="sidebar-bottom">

        <div class="system-mini">

            <div class="online-dot"></div>

            Monitoring service active

        </div>

    </div>

</aside>


<!-- =====================================================
     MAIN
===================================================== -->

<main class="main">


<header class="topbar">

    <div class="page-title">

        <h1>
            Security Operations Center
        </h1>

        <p>
            Automated cloud security monitoring & threat detection
        </p>

    </div>


    <div class="top-actions">

        <div class="refresh-text">
            Auto refresh: 30s
        </div>

        <div class="status-pill">

            <div class="status-dot"></div>

            <span>
                SYSTEM ONLINE
            </span>

        </div>

    </div>

</header>


<section class="content">


<div class="welcome">

    <h2>
        Security Overview
    </h2>

    <p>
        Monitor suspicious cloud activity and security events from your environment.
    </p>

</div>


<!-- KPI CARDS -->

<div class="stats-grid">


<div class="stat-card total">

    <div class="stat-top">

        <div class="stat-label">
            Total Alerts
        </div>

        <div class="stat-icon">
            ◈
        </div>

    </div>

    <div class="stat-number">
        {{ total }}
    </div>

    <div class="stat-description">
        Detected security events
    </div>

</div>


<div class="stat-card critical">

    <div class="stat-top">

        <div class="stat-label">
            Critical
        </div>

        <div class="stat-icon">
            !
        </div>

    </div>

    <div class="stat-number">
        {{ critical }}
    </div>

    <div class="stat-description">
        Immediate attention
    </div>

</div>


<div class="stat-card high">

    <div class="stat-top">

        <div class="stat-label">
            High
        </div>

        <div class="stat-icon">
            ▲
        </div>

    </div>

    <div class="stat-number">
        {{ high }}
    </div>

    <div class="stat-description">
        High-risk activity
    </div>

</div>


<div class="stat-card medium">

    <div class="stat-top">

        <div class="stat-label">
            Medium
        </div>

        <div class="stat-icon">
            ●
        </div>

    </div>

    <div class="stat-number">
        {{ medium }}
    </div>

    <div class="stat-description">
        Suspicious activity
    </div>

</div>


<div class="stat-card low">

    <div class="stat-top">

        <div class="stat-label">
            Low
        </div>

        <div class="stat-icon">
            ✓
        </div>

    </div>

    <div class="stat-number">
        {{ low }}
    </div>

    <div class="stat-description">
        Low-risk activity
    </div>

</div>


</div>


<!-- ANALYTICS -->

<div class="analytics-grid"
     id="analytics">


<div class="panel">

    <div class="panel-header">

        <div>

            <div class="panel-title">
                Alert Severity
            </div>

            <div class="panel-subtitle">
                Distribution of detected threats
            </div>

        </div>

    </div>


    <div class="chart-box">

        <canvas id="severityChart"></canvas>

    </div>

</div>


<div class="panel">

    <div class="panel-header">

        <div>

            <div class="panel-title">
                Security Activity
            </div>

            <div class="panel-subtitle">
                Alert frequency over time
            </div>

        </div>

    </div>


    <div class="chart-box">

        <canvas id="timeChart"></canvas>

    </div>

</div>


</div>


<!-- ALERTS -->

<div class="alert-panel"
     id="alerts">


<div class="alert-header">

    <div class="alert-title">

        <h2>
            Security Alerts
        </h2>

        <p>
            Detected suspicious activity from monitored events
        </p>

    </div>


    <div class="alert-count">

        {{ total }} alerts

    </div>

</div>


<!-- FILTERS -->

<div class="filter-bar">


<div class="search-wrapper">

    <span class="search-icon">
        🔎
    </span>

    <input
        type="text"
        id="searchInput"
        class="search-input"
        placeholder="Search events, users, IP addresses or reasons..."
        onkeyup="filterAlerts()"
    >

</div>


<select
    id="severityFilter"
    class="severity-select"
    onchange="filterAlerts()"
>

    <option value="ALL">
        All Severities
    </option>

    <option value="CRITICAL">
        Critical
    </option>

    <option value="HIGH">
        High
    </option>

    <option value="MEDIUM">
        Medium
    </option>

    <option value="LOW">
        Low
    </option>

</select>


<button
    onclick="clearFilters()"
    class="clear-button"
>
    Clear
</button>


</div>


<!-- TABLE -->

<div class="table-container">

<table id="alertsTable">

<thead>

<tr>

<th>
    Event
</th>

<th>
    User
</th>

<th>
    Source IP
</th>

<th>
    Severity
</th>

<th>
    Detection Reason
</th>

<th>
    Event Time
</th>

</tr>

</thead>


<tbody>

{{ rows | safe }}

</tbody>

</table>

</div>


</div>


<!-- =====================================================
     DEVELOPMENT TEAM
===================================================== -->

<div class="team-section"
     id="team">

    <div class="team-header">

        <h2>
            Development Team
        </h2>

        <p>
            Cloud Sentinel was developed by
        </p>

    </div>


    <div class="team-grid">


        <div class="team-card">

            <div class="team-avatar">
                DP
            </div>

            <div class="team-name">
                Dhanesh P
            </div>

            <div class="team-role">
                PROJECT DEVELOPER
            </div>

        </div>


        <div class="team-card">

            <div class="team-avatar">
                AR
            </div>

            <div class="team-name">
                Amith R
            </div>

            <div class="team-role">
                PROJECT DEVELOPER
            </div>

        </div>


        <div class="team-card">

            <div class="team-avatar">
                AS
            </div>

            <div class="team-name">
                Amarsurya S
            </div>

            <div class="team-role">
                PROJECT DEVELOPER
            </div>

        </div>


        <div class="team-card">

            <div class="team-avatar">
                NK
            </div>

            <div class="team-name">
                Nanda Kishore ES
            </div>

            <div class="team-role">
                PROJECT DEVELOPER
            </div>

        </div>


    </div>

</div>


</section>


<div class="footer">

    Cloud Sentinel
    • Python-Based Automated Cloud Security Monitoring
    • Flask
    • SQLite

    <br><br>

    Developed by Dhanesh P • Amith R • Amarsurya S • Nanda Kishore ES

</div>


</main>


<!-- =====================================================
     ALERT DETAILS MODAL
===================================================== -->

<div class="modal"
     id="alertModal"
     onclick="closeOutside(event)">

    <div class="modal-box">

        <div class="modal-header">

            <h3>
                Security Alert Details
            </h3>

            <button
                class="close-button"
                onclick="closeModal()"
            >
                ×
            </button>

        </div>


        <div class="modal-content">

            <div class="detail-grid">


                <div class="detail-item">

                    <div class="detail-label">
                        Event
                    </div>

                    <div
                        class="detail-value"
                        id="detailEvent"
                    ></div>

                </div>


                <div class="detail-item">

                    <div class="detail-label">
                        Severity
                    </div>

                    <div
                        class="detail-value"
                        id="detailSeverity"
                    ></div>

                </div>


                <div class="detail-item">

                    <div class="detail-label">
                        Username
                    </div>

                    <div
                        class="detail-value"
                        id="detailUser"
                    ></div>

                </div>


                <div class="detail-item">

                    <div class="detail-label">
                        Source IP
                    </div>

                    <div
                        class="detail-value"
                        id="detailIP"
                    ></div>

                </div>


                <div class="detail-item">

                    <div class="detail-label">
                        Event Time
                    </div>

                    <div
                        class="detail-value"
                        id="detailTime"
                    ></div>

                </div>


                <div class="detail-item detail-reason">

                    <div class="detail-label">
                        Detection Reason
                    </div>

                    <div
                        class="detail-value"
                        id="detailReason"
                    ></div>

                </div>


            </div>

        </div>

    </div>

</div>


<script>

/* =====================================================
   SEVERITY CHART
===================================================== */

const severityCanvas =
    document.getElementById("severityChart");


new Chart(
    severityCanvas,
    {

        type: "doughnut",

        data: {

            labels: [
                "Critical",
                "High",
                "Medium",
                "Low"
            ],

            datasets: [{

                data: [
                    {{ critical }},
                    {{ high }},
                    {{ medium }},
                    {{ low }}
                ],

                backgroundColor: [
                    "#ef4444",
                    "#f97316",
                    "#facc15",
                    "#22c55e"
                ],

                borderWidth: 0,

                hoverOffset: 7

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            cutout: "72%",

            plugins: {

                legend: {

                    position: "bottom",

                    labels: {

                        color: "#94a3b8",

                        padding: 16,

                        usePointStyle: true,

                        pointStyle: "circle",

                        font: {
                            size: 9
                        }

                    }

                },

                tooltip: {

                    backgroundColor: "#111827",

                    borderColor: "#263449",

                    borderWidth: 1,

                    titleColor: "#fff",

                    bodyColor: "#94a3b8"

                }

            }

        }

    }
);


/* =====================================================
   TIME CHART
===================================================== */

const timeCanvas =
    document.getElementById("timeChart");


new Chart(
    timeCanvas,
    {

        type: "line",

        data: {

            labels: {{ time_labels | safe }},

            datasets: [{

                label: "Security Alerts",

                data: {{ time_values | safe }},

                borderColor: "#38bdf8",

                backgroundColor:
                    "rgba(56,189,248,.07)",

                borderWidth: 2,

                pointRadius: 3,

                pointBackgroundColor: "#38bdf8",

                pointBorderColor: "#0d1626",

                pointBorderWidth: 2,

                fill: true,

                tension: .35

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            interaction: {

                intersect: false,

                mode: "index"

            },

            plugins: {

                legend: {
                    display: false
                },

                tooltip: {

                    backgroundColor: "#111827",

                    borderColor: "#263449",

                    borderWidth: 1,

                    titleColor: "#fff",

                    bodyColor: "#94a3b8"

                }

            },

            scales: {

                x: {

                    grid: {

                        color:
                            "rgba(51,65,85,.2)"

                    },

                    ticks: {

                        color: "#64748b",

                        font: {
                            size: 8
                        }

                    }

                },

                y: {

                    beginAtZero: true,

                    grid: {

                        color:
                            "rgba(51,65,85,.2)"

                    },

                    ticks: {

                        color: "#64748b",

                        precision: 0,

                        font: {
                            size: 8
                        }

                    }

                }

            }

        }

    }
);


/* =====================================================
   SEARCH + FILTER
===================================================== */

function filterAlerts() {

    const search =
        document
        .getElementById("searchInput")
        .value
        .toLowerCase();

    const severity =
        document
        .getElementById("severityFilter")
        .value;

    const rows =
        document
        .querySelectorAll(".alert-row");


    rows.forEach(row => {

        const text =
            row.innerText.toLowerCase();

        const rowSeverity =
            row.dataset.severity;


        const matchesSearch =
            text.includes(search);

        const matchesSeverity =
            severity === "ALL" ||
            rowSeverity === severity;


        row.style.display =
            matchesSearch &&
            matchesSeverity
            ? ""
            : "none";

    });

}


/* =====================================================
   CLEAR FILTERS
===================================================== */

function clearFilters() {

    document
    .getElementById("searchInput")
    .value = "";

    document
    .getElementById("severityFilter")
    .value = "ALL";

    filterAlerts();

}


/* =====================================================
   ALERT MODAL
===================================================== */

function showAlert(
    event,
    user,
    ip,
    severity,
    reason,
    time
) {

    document
    .getElementById("detailEvent")
    .innerText = event;

    document
    .getElementById("detailUser")
    .innerText = user;

    document
    .getElementById("detailIP")
    .innerText = ip;

    document
    .getElementById("detailSeverity")
    .innerText = severity;

    document
    .getElementById("detailReason")
    .innerText = reason;

    document
    .getElementById("detailTime")
    .innerText = time;

    document
    .getElementById("alertModal")
    .classList.add("show");
}


function closeModal() {

    document
    .getElementById("alertModal")
    .classList.remove("show");
}


function closeOutside(event) {

    if (
        event.target.id === "alertModal"
    ) {

        closeModal();

    }

}


/* =====================================================
   NAVIGATION
===================================================== */

function scrollToAlerts() {

    document
    .getElementById("alerts")
    .scrollIntoView({
        behavior: "smooth"
    });

}


function scrollToAnalytics() {

    document
    .getElementById("analytics")
    .scrollIntoView({
        behavior: "smooth"
    });

}


/* =====================================================
   ESCAPE KEY
===================================================== */

document.addEventListener(
    "keydown",
    function(event) {

        if (event.key === "Escape") {

            closeModal();

        }

    }
);

</script>


</body>

</html>
"""


import os

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )

    
