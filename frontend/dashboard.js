const API_BASE = window.__CYBERSENTINEL_API__ ?? `${window.location.origin.replace(/\/$/, "")}`;

const selectors = {
  status: document.getElementById("status"),
  intelTable: document.querySelector("#intel-table tbody"),
  sshTable: document.querySelector("#ssh-table tbody"),
  apacheTable: document.querySelector("#apache-table tbody"),
  alertsTable: document.querySelector("#alerts-table tbody"),
  totals: {
    ssh: document.getElementById("total-ssh"),
    apache: document.getElementById("total-apache"),
    alerts: document.getElementById("total-alerts"),
  },
  buttons: {
    fetch: document.getElementById("fetch-intel"),
    parse: document.getElementById("parse-logs"),
    correlate: document.getElementById("run-correlation"),
  },
};

const state = {
  charts: {
    sshTrend: null,
    sshTopIps: null,
    apacheStatus: null,
    alertSeverity: null,
  },
  pending: new Set(),
};

function setPending(key, flag) {
  if (flag) {
    state.pending.add(key);
  } else {
    state.pending.delete(key);
  }
  const isBusy = state.pending.size > 0;
  Object.values(selectors.buttons).forEach((btn) => {
    btn.disabled = isBusy;
    btn.setAttribute("aria-busy", String(isBusy));
  });
}

async function fetchJson(path, options = {}) {
  const url = `${API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;
  try {
    const response = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!response.ok) {
      const message = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${message}`);
    }
    return await response.json();
  } catch (error) {
    updateStatus(`Error: ${error.message}`, true);
    throw error;
  }
}

function updateStatus(message, isError = false) {
  selectors.status.textContent = message;
  selectors.status.classList.toggle("error", isError);
}

function renderTableRows(tableBody, rows, fallbackColumns = 5) {
  tableBody.innerHTML = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = fallbackColumns;
    td.textContent = "No data available.";
    tr.appendChild(td);
    tableBody.appendChild(tr);
    return;
  }
  const fragment = document.createDocumentFragment();
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    row.forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value ?? "-";
      tr.appendChild(td);
    });
    fragment.appendChild(tr);
  });
  tableBody.appendChild(fragment);
}

function updateTotals(totals = {}) {
  const { ssh_events = 0, apache_events = 0, alerts = 0 } = totals;
  selectors.totals.ssh.textContent = ssh_events;
  selectors.totals.apache.textContent = apache_events;
  selectors.totals.alerts.textContent = alerts;
}

function buildChartConfig(type, data, overrides = {}) {
  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: "#9da6c6",
        },
      },
      tooltip: {
        backgroundColor: "rgba(10, 18, 44, 0.95)",
        borderColor: "rgba(148, 163, 184, 0.22)",
        borderWidth: 1,
        titleColor: "#f4f6ff",
        bodyColor: "#e2e8f0",
      },
    },
    scales: {
      x: {
        ticks: { color: "#9da6c6" },
        grid: { color: "rgba(148, 163, 184, 0.1)" },
      },
      y: {
        ticks: { color: "#9da6c6" },
        grid: { color: "rgba(148, 163, 184, 0.1)" },
      },
    },
  };

  return {
    type,
    data,
    options: {
      ...baseOptions,
      ...overrides,
      plugins: { ...baseOptions.plugins, ...(overrides.plugins ?? {}) },
      scales: overrides.scales ?? baseOptions.scales,
    },
  };
}

function renderChart(key, ctxId, config) {
  const ctx = document.getElementById(ctxId);
  if (!ctx) return;
  if (state.charts[key]) {
    state.charts[key].destroy();
  }
  state.charts[key] = new Chart(ctx, config);
}

async function loadIntel() {
  setPending("intel", true);
  updateStatus("Fetching threat intelligence...");
  try {
    const payload = await fetchJson("/api/intel");
    renderTableRows(
      selectors.intelTable,
      payload.data.map((item) => [
        item.indicator,
        item.type,
        item.source,
        item.last_seen ?? item.first_seen ?? "-",
        item.confidence ?? "-",
      ])
    );
    updateStatus(`Loaded ${payload.count} indicators.`);
  } finally {
    setPending("intel", false);
  }
}

async function loadLogs() {
  setPending("logs", true);
  try {
    const [sshPayload, apachePayload] = await Promise.all([
      fetchJson("/api/logs?source=ssh"),
      fetchJson("/api/logs?source=apache"),
    ]);

    renderTableRows(
      selectors.sshTable,
      sshPayload.data.map((item) => [
        item.event_time,
        item.ip_address,
        item.username,
        item.meta?.message ?? item.raw,
      ])
    );

    renderTableRows(
      selectors.apacheTable,
      apachePayload.data.map((item) => [
        item.event_time,
        item.ip_address,
        item.request,
        item.status_code,
      ])
    );
  } finally {
    setPending("logs", false);
  }
}

async function loadAlerts() {
  const payload = await fetchJson("/api/alerts");
  renderTableRows(
    selectors.alertsTable,
    payload.data.map((item) => [
      item.created_at ?? item.event_time ?? "-",
      item.indicator,
      item.log_source,
      item.severity,
      item.message,
    ])
  );
}

function renderAnalyticsCharts(metrics) {
  updateTotals(metrics.totals);

  const sshTrendLabels = metrics.ssh_failures_over_time.map((entry) => entry.time);
  const sshTrendValues = metrics.ssh_failures_over_time.map((entry) => entry.count);
  renderChart(
    "sshTrend",
    "ssh-trend-chart",
    buildChartConfig("line", {
      labels: sshTrendLabels,
      datasets: [
        {
          label: "SSH Failures",
          data: sshTrendValues,
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.15)",
          tension: 0.35,
          fill: true,
        },
      ],
    })
  );

  const sshTopIpLabels = metrics.ssh_top_ips.map((entry) => entry.ip);
  const sshTopIpValues = metrics.ssh_top_ips.map((entry) => entry.count);
  renderChart(
    "sshTopIps",
    "ssh-top-ips-chart",
    buildChartConfig("bar", {
      labels: sshTopIpLabels,
      datasets: [
        {
          label: "Attempts",
          data: sshTopIpValues,
          backgroundColor: "rgba(14, 165, 233, 0.65)",
          borderRadius: 12,
        },
      ],
    })
  );

  const apacheStatusLabels = metrics.apache_status_counts.map((entry) => entry.status);
  const apacheStatusValues = metrics.apache_status_counts.map((entry) => entry.count);
  renderChart(
    "apacheStatus",
    "apache-status-chart",
    buildChartConfig(
      "doughnut",
      {
        labels: apacheStatusLabels,
        datasets: [
          {
            data: apacheStatusValues,
            backgroundColor: [
              "#38bdf8",
              "#f97316",
              "#f87171",
              "#22c55e",
              "#a855f7",
            ],
            borderColor: "rgba(5, 10, 31, 0.9)",
            borderWidth: 2,
          },
        ],
      },
      {
        cutout: "60%",
      }
    )
  );

  const alertSeverityLabels = metrics.alert_severity_counts.map((entry) => entry.severity);
  const alertSeverityValues = metrics.alert_severity_counts.map((entry) => entry.count);
  renderChart(
    "alertSeverity",
    "alert-severity-chart",
    buildChartConfig("polarArea", {
      labels: alertSeverityLabels,
      datasets: [
        {
          data: alertSeverityValues,
          backgroundColor: ["#f87171", "#facc15", "#34d399", "#38bdf8"],
        },
      ],
    })
  );
}

async function loadAnalytics() {
  const metrics = await fetchJson("/api/analytics/summary");
  renderAnalyticsCharts(metrics);
}

async function runParseLogs() {
  setPending("parse", true);
  updateStatus("Parsing log files...");
  try {
    const payload = await fetchJson("/api/logs/parse", { method: "POST" });
    updateStatus(
      `Parsed logs: SSH=${payload.sources.ssh ?? 0}, Apache=${payload.sources.apache ?? 0}`
    );
    await loadLogs();
    await loadAnalytics();
  } finally {
    setPending("parse", false);
  }
}

async function runFetchIntel() {
  setPending("fetch", true);
  updateStatus("Fetching latest indicators...");
  try {
    const payload = await fetchJson("/api/intel/fetch", { method: "POST" });
    updateStatus(`Fetched ${payload.fetched} indicators; stored ${payload.stored}.`);
    await loadIntel();
    await loadAnalytics();
  } finally {
    setPending("fetch", false);
  }
}

async function runCorrelationWorkflow() {
  setPending("correlate", true);
  updateStatus("Executing correlation workflow...");
  try {
    const payload = await fetchJson("/api/workflow/refresh", { method: "POST" });
    updateStatus(
      `Workflow completed: intel=${payload.intel?.fetched ?? 0}, logs=${
        payload.logs?.sources?.ssh ?? 0
      }/${payload.logs?.sources?.apache ?? 0}, alerts=${payload.correlation?.generated ?? 0}`
    );
    await Promise.all([loadIntel(), loadLogs(), loadAlerts()]);
    renderAnalyticsCharts(payload.analytics);
  } finally {
    setPending("correlate", false);
  }
}

function registerEventHandlers() {
  selectors.buttons.fetch.addEventListener("click", () => {
    runFetchIntel().catch(() => {});
  });

  selectors.buttons.parse.addEventListener("click", () => {
    runParseLogs().catch(() => {});
  });

  selectors.buttons.correlate.addEventListener("click", () => {
    runCorrelationWorkflow().catch(() => {});
  });
}

function stampFooterYear() {
  const footerYear = document.getElementById("footer-year");
  if (footerYear) {
    footerYear.textContent = String(new Date().getFullYear());
  }
}

async function bootstrap() {
  Chart.defaults.color = "#e2e8f0";
  Chart.defaults.font.family = getComputedStyle(document.documentElement).getPropertyValue("font-family");

  stampFooterYear();
  registerEventHandlers();
  updateStatus("Loading dashboard...");

  try {
    await Promise.all([loadIntel(), loadLogs(), loadAlerts(), loadAnalytics()]);
    updateStatus("Dashboard ready.");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load initial data.", true);
  }
}

window.addEventListener("DOMContentLoaded", bootstrap);
