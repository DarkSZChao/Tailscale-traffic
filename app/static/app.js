const state = {
  payload: null,
  selectedAliasTarget: null,
  activePolicyTarget: null,
  activePolicyRule: "quota",
  activeAccessBlockMode: "temporary",
  activeWebsiteTarget: null,
  activeWebsitePeriod: "24h",
  panelTimezone: "",
  panelTimezoneFormatter: null,
  settingsLoaded: false,
  chartBars: [],
  currentPage: "overview",
  rules: [],
  expandedUsers: new Set(),
};

const $ = (selector) => document.querySelector(selector);
const monthPicker = $("#monthPicker");
const chart = $("#usageChart");
const tooltip = $("#chartTooltip");
const PAGE_META = {
  overview: {
    eyebrow: "EXIT NODE / OVERVIEW",
    title: "概览",
    description: "查看当月总流量、来源构成与每日趋势。",
    usesMonth: true,
  },
  users: {
    eyebrow: "EXIT ACCESS / DEVICES",
    title: "出口控制",
    description: "查看用户及其所属设备的出口用量、访问记录，并直接管理。",
    usesMonth: true,
  },
  rules: {
    eyebrow: "TRAFFIC & ACCESS / POLICIES",
    title: "规则",
    description: "按用户和设备分别管理流量上限封禁与手动封禁。",
    usesMonth: false,
  },
  settings: {
    eyebrow: "CONFIG / SECURITY",
    title: "设置",
    description: "调整采集、网站记录、统计口径和面板登录密码。",
    usesMonth: false,
  },
  logs: {
    eyebrow: "SYSTEM / AUDIT LOGS",
    title: "日志",
    description: "查看登录、配置、规则操作和采集器状态记录。",
    usesMonth: false,
  },
};

const POLICY_RULE_REGISTRY = Object.freeze({
  quota: {
    panel: "quota",
    submit: () => savePolicy(),
  },
  manual: {
    panel: "access",
    submit: () => setAccessBlock(state.activeAccessBlockMode === "permanent"),
  },
});

function selectPolicyRule(type) {
  const selectedType = POLICY_RULE_REGISTRY[type] ? type : "quota";
  state.activePolicyRule = selectedType;
  document.querySelectorAll("[data-policy-rule]").forEach((button) => {
    const selected = button.dataset.policyRule === selectedType;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-checked", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll("[data-policy-rule-panel]").forEach((panel) => {
    const selected = panel.dataset.policyRulePanel
      === POLICY_RULE_REGISTRY[selectedType].panel;
    panel.classList.toggle("active", selected);
    panel.setAttribute("aria-hidden", String(!selected));
    panel.inert = !selected;
  });
}

function submitSelectedPolicyRule() {
  POLICY_RULE_REGISTRY[state.activePolicyRule]?.submit();
}

function updateAccessBlockMode(permanent) {
  const durationField = $("#accessBlockDurationField");
  durationField.classList.toggle("mode-hidden", permanent);
  durationField.setAttribute("aria-hidden", String(permanent));
  durationField.inert = permanent;
  const button = $("#saveAccessBlock");
  button.textContent = permanent ? "应用永久封禁" : "应用临时封禁";
}

function selectAccessBlockMode(mode) {
  const selectedMode = mode === "permanent" ? "permanent" : "temporary";
  state.activeAccessBlockMode = selectedMode;
  document.querySelectorAll("[data-access-block-mode]").forEach((button) => {
    const selected = button.dataset.accessBlockMode === selectedMode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-checked", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  updateAccessBlockMode(selectedMode === "permanent");
}

function pageFromHash() {
  const page = window.location.hash.slice(1);
  if (page === "system") return "settings";
  return PAGE_META[page] ? page : "overview";
}

function showPage(page) {
  const selectedPage = PAGE_META[page] ? page : "overview";
  const meta = PAGE_META[selectedPage];
  state.currentPage = selectedPage;

  document.querySelectorAll("[data-page-view]").forEach((view) => {
    view.hidden = view.dataset.pageView !== selectedPage;
  });
  document.querySelectorAll(".nav-item").forEach((link) => {
    const active = link.dataset.page === selectedPage;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });

  $("#pageEyebrow").textContent = meta.eyebrow;
  $("#pageTitle").textContent = meta.title;
  $("#pageDescription").textContent = meta.description;
  $("#monthControl").hidden = !meta.usesMonth;
  document.title = `${meta.title} · Tailscale 流量控制面板`;

  if (selectedPage === "overview") {
    window.requestAnimationFrame(drawChart);
  } else if (selectedPage === "rules") {
    loadRules();
  } else if (selectedPage === "settings") {
    loadSettings();
    loadSessions();
  } else if (selectedPage === "logs") {
    loadLogs();
  }
}

function formatBytes(bytes, compact = false) {
  const value = Number(bytes || 0);
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  if (value === 0) return "0 B";
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1000)), units.length - 1);
  const number = value / 1000 ** index;
  const digits = compact ? (number >= 100 ? 0 : number >= 10 ? 1 : 2) : (number >= 10 ? 1 : 2);
  return `${number.toFixed(digits)} ${units[index]}`;
}

function formatUsagePair(recentBytes, monthBytes) {
  const recent = formatBytes(recentBytes, true).replace(" ", "");
  const month = formatBytes(monthBytes, true).replace(" ", "");
  return `${recent}/${month}`;
}

function usagePeriodLabel() {
  return state.payload?.month === state.payload?.current_month
    ? "过去1天/当月"
    : `过去1天/${state.payload?.month || "所选月"}`;
}

function formatTime(value) {
  if (!value) return "尚未采集";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(seconds) {
  const value = Math.max(0, Number(seconds || 0));
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (days) return `${days}天 ${hours}小时`;
  if (hours) return `${hours}小时 ${minutes}分钟`;
  return `${minutes}分钟`;
}

function currentMonth() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
}

function updateMonthReset() {
  $("#resetMonth").hidden = !monthPicker.value
    || monthPicker.value === currentMonth();
}

function formatLimitInput(bytes) {
  if (!bytes) return { value: "", unit: "GB" };
  const unit = bytes >= 1_000_000_000_000 ? "TB" : "GB";
  const divisor = unit === "TB" ? 1_000_000_000_000 : 1_000_000_000;
  return {
    value: String(Number((bytes / divisor).toFixed(3))),
    unit,
  };
}

function formatBlockUntil(value) {
  if (!value) return "—";
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return value;
  return timestamp.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function hasQuotaRule(policy) {
  return Boolean(policy && (policy.quota_exists || policy.limit_bytes));
}

function hasAccessRule(policy) {
  return Boolean(policy?.access_exists);
}

function hasPolicyRule(policy) {
  return hasQuotaRule(policy) || hasAccessRule(policy);
}

function ruleBadge(label, className = "", title = "") {
  const classes = `quota-badge${className ? ` ${className}` : ""}`;
  const titleAttribute = title ? ` title="${escapeHtml(title)}"` : "";
  return `<span class="${classes}"${titleAttribute}>${label}</span>`;
}

function policyBadges(policy) {
  if (!policy) return "";
  const badges = [];
  if (hasQuotaRule(policy)) {
    if (policy.quota_enabled === false) {
      badges.push(ruleBadge("限额未启用", "disabled-rule"));
    } else if (policy.quota_blocked) {
      badges.push(ruleBadge("流量封禁", "blocked"));
    } else if (policy.bypassed) {
      badges.push(ruleBadge("本月已解锁", "bypassed"));
    } else {
      badges.push(ruleBadge("有限额"));
    }
  }
  if (hasAccessRule(policy)) {
    if (policy.access_enabled === false) {
      badges.push(ruleBadge("封禁未启用", "disabled-rule"));
    } else if (policy.access_active) {
      const label = policy.block_mode === "permanent" ? "永久封禁" : "临时封禁";
      badges.push(ruleBadge(label, "blocked"));
    } else {
      badges.push(ruleBadge("封禁已到期"));
    }
  }
  return badges.join("");
}

function partialDevicePolicyBadges(userPolicy, devices) {
  const badges = [];
  if (!hasQuotaRule(userPolicy)) {
    const quotaPolicies = devices
      .map((device) => device.policy)
      .filter(hasQuotaRule);
    if (quotaPolicies.length) {
      const title = `${quotaPolicies.length} 台设备设有流量上限规则`;
      if (quotaPolicies.some((policy) => policy.quota_blocked)) {
        badges.push(ruleBadge("部分设备流量封禁", "blocked", title));
      } else if (quotaPolicies.some((policy) => policy.quota_enabled !== false)) {
        badges.push(ruleBadge("部分设备有限额", "", title));
      } else {
        badges.push(ruleBadge("部分设备限额未启用", "disabled-rule", title));
      }
    }
  }
  if (!hasAccessRule(userPolicy)) {
    const accessPolicies = devices
      .map((device) => device.policy)
      .filter(hasAccessRule);
    if (accessPolicies.length) {
      const title = `${accessPolicies.length} 台设备设有手动封禁规则`;
      if (accessPolicies.some(
        (policy) => policy.access_enabled !== false && policy.access_active
      )) {
        badges.push(ruleBadge("部分设备封禁", "blocked", title));
      } else if (accessPolicies.some((policy) => policy.access_enabled !== false)) {
        badges.push(ruleBadge("部分设备封禁已到期", "", title));
      } else {
        badges.push(ruleBadge("部分设备封禁未启用", "disabled-rule", title));
      }
    }
  }
  return badges.join("");
}

function policySummary(policy) {
  if (!policy) return "未设置";
  const summaries = [];
  if (policy.limit_bytes) {
    summaries.push(policy.quota_enabled
      ? `流量上限 ${formatBytes(policy.usage_bytes, true)} / ${formatBytes(policy.limit_bytes, true)}`
      : "流量上限封禁已停用");
  }
  if (policy.access_exists) {
    summaries.push(policy.access_enabled
      ? (policy.access_active
          ? (policy.block_mode === "permanent" ? "永久封禁" : "临时封禁")
          : "手动封禁已到期")
      : "手动封禁已停用");
  }
  return summaries.join("；") || "未设置";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function initials(name) {
  const text = String(name || "?").trim();
  return [...text].slice(0, 2).join("").toUpperCase();
}

function requireLogin(response) {
  if (response.status === 401) {
    window.location.replace("/login");
    throw new Error("登录状态已过期");
  }
  return response;
}

function setCollectorStatus(collector, lastCollect, dashboardUptime = 0) {
  const status = $("#collectorStatus");
  const healthy = Boolean(collector?.healthy);
  status.classList.toggle("error", !healthy);
  $("#collectorStatusText").textContent = healthy ? "采集正常" : "采集异常";
  status.title = collector?.error || "";
  $("#lastCollect").textContent = `更新于 ${formatTime(lastCollect)}`;
  $("#systemUptime").textContent = formatDuration(
    collector?.uptime_seconds ?? dashboardUptime
  );
}

function setPanelTimezone(timezone) {
  const normalized = String(timezone || "UTC");
  if (state.panelTimezone === normalized && state.panelTimezoneFormatter) {
    return;
  }
  state.panelTimezone = normalized;
  $("#panelTimezone").textContent = normalized;
  $("#panelTimezone").title = normalized;
  try {
    state.panelTimezoneFormatter = new Intl.DateTimeFormat("zh-CN", {
      timeZone: normalized,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    });
  } catch {
    state.panelTimezoneFormatter = null;
  }
  updatePanelTimezoneClock();
}

function updatePanelTimezoneClock() {
  const clock = $("#panelTimezoneTime");
  clock.textContent = state.panelTimezoneFormatter
    ? state.panelTimezoneFormatter.format(new Date())
    : "时区不可用";
  clock.dateTime = new Date().toISOString();
}

function renderSummary(summary) {
  const percent = summary.quota ? summary.usage_ratio * 100 : 0;
  $("#totalUsage").textContent = formatBytes(summary.total, true);
  $("#usagePercent").textContent = summary.quota ? `${percent.toFixed(1)}%` : "未设置额度";
  $("#remainingUsage").textContent = summary.quota ? formatBytes(summary.remaining, true) : "—";
  $("#quotaUsage").textContent = summary.quota ? formatBytes(summary.quota, true) : "—";
  $("#downloadUsage").textContent = formatBytes(summary.download, true);
  $("#uploadUsage").textContent = formatBytes(summary.upload, true);
  $("#forecastUsage").textContent = formatBytes(summary.forecast, true);
  $("#tailnetUsage").textContent = formatBytes(summary.tailnet_total, true);
  $("#externalUsage").textContent = formatBytes(summary.external_total, true);
  const unknownScope = $("#unknownScopeUsage");
  unknownScope.hidden = !summary.unknown_total;
  unknownScope.querySelector("b").textContent = formatBytes(summary.unknown_total, true);

  const progress = $("#quotaProgress");
  progress.style.width = `${Math.min(100, percent)}%`;
  progress.classList.toggle("over", percent >= 90);
}

async function responseError(response, fallback) {
  try {
    const payload = await response.json();
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return payload.detail.map((item) => {
        const field = Array.isArray(item.loc) ? item.loc.at(-1) : "字段";
        return `${field}: ${item.msg || "值无效"}`;
      }).join("；");
    }
  } catch {
    // 使用后备提示。
  }
  return fallback;
}

async function loadSettings() {
  const message = $("#settingsMessage");
  try {
    const response = requireLogin(await fetch("/api/settings"));
    if (!response.ok) {
      throw new Error(await responseError(response, "读取设置失败"));
    }
    const payload = await response.json();
    const config = payload.config || {};
    $("#settingQuota").value = config.monthly_quota_gb ?? 3000;
    $("#settingInterval").value = config.collect_interval ?? 10;
    $("#settingRetention").value = config.website_retention_days ?? 180;
    $("#settingTimezone").value = config.timezone || "UTC";
    $("#configModifiedAt").textContent = formatTime(
      payload.config_modified_at
    );
    $("#projectVersion").textContent = payload.version || "unknown";
    state.settingsLoaded = true;
    message.textContent = payload.website?.error || "";
  } catch (error) {
    message.textContent = error.message;
    message.classList.add("error");
  }
}

async function saveSettings(event) {
  event.preventDefault();
  const button = $("#saveSettings");
  const message = $("#settingsMessage");
  button.disabled = true;
  message.classList.remove("error", "success");
  message.textContent = "正在保存…";
  try {
    const response = requireLogin(
      await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          monthly_quota_gb: Number($("#settingQuota").value),
          collect_interval: Number($("#settingInterval").value),
          website_retention_days: Number($("#settingRetention").value),
          timezone: $("#settingTimezone").value.trim(),
        }),
      })
    );
    if (!response.ok) {
      throw new Error(await responseError(response, "保存设置失败"));
    }
    message.classList.add("success");
    message.textContent = "config.yaml 已保存，collector 会在下一轮自动应用。";
    const payload = await response.json();
    $("#configModifiedAt").textContent = formatTime(
      payload.config_modified_at
    );
    showToast("config.yaml 已更新");
    await loadDashboard();
  } catch (error) {
    message.classList.add("error");
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function changePanelPassword(event) {
  event.preventDefault();
  const currentPassword = $("#currentPassword");
  const newPassword = $("#newPassword");
  const confirmPassword = $("#confirmNewPassword");
  const button = $("#changePassword");
  const message = $("#passwordMessage");
  message.classList.remove("error", "success");
  if (newPassword.value !== confirmPassword.value) {
    message.classList.add("error");
    message.textContent = "两次输入的新密码不一致";
    confirmPassword.select();
    return;
  }
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch("/api/settings/password", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: currentPassword.value,
          new_password: newPassword.value,
        }),
      })
    );
    if (!response.ok) {
      throw new Error(await responseError(response, "修改密码失败"));
    }
    $("#passwordForm").reset();
    message.classList.add("success");
    message.textContent = "密码已更新，其他浏览器中的旧会话已经失效。";
    showToast("面板密码已更新");
    await loadSessions();
  } catch (error) {
    message.classList.add("error");
    message.textContent = error.message;
    currentPassword.select();
  } finally {
    button.disabled = false;
  }
}

async function loadSessions() {
  const list = $("#sessionList");
  const message = $("#sessionMessage");
  message.classList.remove("error");
  try {
    const response = requireLogin(await fetch("/api/auth/sessions"));
    if (!response.ok) {
      throw new Error(await responseError(response, "读取登录设备失败"));
    }
    const payload = await response.json();
    const sessions = payload.sessions || [];
    list.innerHTML = sessions.length
      ? sessions.map((session) => {
        const recognizedName = session.recognized_device_name || "";
        const clientDetails = [
          recognizedName ? session.device_name : "",
          session.ip_address || "未知地址",
        ].filter(Boolean).join(" · ");
        return `
        <article class="session-row">
          <div class="session-meta">
            <strong>${escapeHtml(recognizedName || session.device_name)}</strong>
            <span>${escapeHtml(clientDetails)}</span>
          </div>
          <p>
            最近活动 ${escapeHtml(formatTime(session.last_seen_at))}<br>
            <span class="log-level">${session.remembered ? "记住 30 天" : "浏览器会话"}</span>
            ${session.current ? '<span class="current-session"> · 当前设备</span>' : ""}
          </p>
          <button type="button" data-revoke-session="${escapeHtml(session.session_id)}">
            ${session.current ? "退出当前设备" : "撤销登录"}
          </button>
        </article>
      `;
      }).join("")
      : '<div class="loading-row">没有有效的登录设备。</div>';
    list.querySelectorAll("[data-revoke-session]").forEach((button) => {
      button.addEventListener("click", () => revokeSession(button));
    });
    message.textContent = "";
  } catch (error) {
    message.textContent = error.message;
    message.classList.add("error");
  }
}

async function revokeSession(button) {
  if (!window.confirm("确定退出这个登录设备吗？")) return;
  button.disabled = true;
  try {
    const response = requireLogin(await fetch(
      `/api/auth/sessions/${encodeURIComponent(button.dataset.revokeSession)}`,
      { method: "DELETE" }
    ));
    if (!response.ok) {
      throw new Error(await responseError(response, "退出设备失败"));
    }
    const payload = await response.json();
    if (payload.current) {
      window.location.replace("/login");
      return;
    }
    showToast("登录设备已退出");
    await loadSessions();
  } catch (error) {
    $("#sessionMessage").textContent = error.message;
    $("#sessionMessage").classList.add("error");
    button.disabled = false;
  }
}

async function logoutAllDevices() {
  if (!window.confirm("确定退出所有设备吗？当前浏览器也会退出。")) return;
  const button = $("#logoutAllDevices");
  button.disabled = true;
  try {
    await fetch("/api/auth/sessions/logout-all", { method: "POST" });
  } finally {
    window.location.replace("/login");
  }
}

const LOG_CATEGORY_GROUPS = [
  { key: "operation", label: "操作日志" },
  { key: "system", label: "系统状态日志" },
  { key: "auth", label: "登录安全日志" },
];

function logRow(log, includeCategory = true) {
  const isError = log.level === "error" || log.level === "warning";
  const action = includeCategory
    ? `${log.category} · ${log.action}`
    : log.action;
  return `
    <article class="log-row${isError ? " error" : ""}">
      <div class="log-meta">
        <strong>${escapeHtml(formatTime(log.created_at))}</strong>
        <span title="${escapeHtml(action)}">${escapeHtml(action)}</span>
      </div>
      <p title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</p>
      <span class="log-level">${escapeHtml(log.level.toUpperCase())}</span>
    </article>
  `;
}

function renderLogsByCategory(logs) {
  const list = $("#logsList");
  if (!logs.length) {
    list.innerHTML = '<div class="loading-row">没有符合条件的日志。</div>';
    return;
  }

  const grouped = new Map();
  logs.forEach((log) => {
    if (!grouped.has(log.category)) grouped.set(log.category, []);
    grouped.get(log.category).push(log);
  });
  const knownKeys = new Set(LOG_CATEGORY_GROUPS.map((group) => group.key));
  const groups = [
    ...LOG_CATEGORY_GROUPS.filter((group) => grouped.has(group.key)),
    ...[...grouped.keys()]
      .filter((category) => !knownKeys.has(category))
      .sort()
      .map((category) => ({ key: category, label: `其他日志 · ${category}` })),
  ];

  list.innerHTML = groups.map((group) => {
    const entries = grouped.get(group.key) || [];
    return `
      <section class="log-category-group">
        <div class="log-category-heading">
          <h3>${escapeHtml(group.label)}</h3>
          <span>${entries.length} 条</span>
        </div>
        <div class="log-category-rows">
          ${entries.map((log) => logRow(log, false)).join("")}
        </div>
      </section>
    `;
  }).join("");
}

function renderRecentLogs(logs) {
  const list = $("#recentLogs");
  list.innerHTML = logs.length
    ? logs.map(logRow).join("")
    : '<div class="loading-row">暂时没有日志。</div>';
}

async function loadLogs() {
  const list = $("#logsList");
  const message = $("#logsMessage");
  message.classList.remove("error");
  const params = new URLSearchParams();
  if ($("#logDate").value) params.set("day", $("#logDate").value);
  if ($("#logKeyword").value.trim()) {
    params.set("keyword", $("#logKeyword").value.trim());
  }
  try {
    const query = params.toString();
    const response = requireLogin(await fetch(
      `/api/logs${query ? `?${query}` : ""}`
    ));
    if (!response.ok) {
      throw new Error(await responseError(response, "读取日志失败"));
    }
    const payload = await response.json();
    renderLogsByCategory(payload.logs);
    message.textContent = "";
  } catch (error) {
    message.textContent = error.message;
    message.classList.add("error");
  }
}

async function clearLogs() {
  if (!window.confirm("确定清理全部日志吗？此操作不可撤销。")) return;
  const button = $("#clearLogs");
  button.disabled = true;
  try {
    const response = requireLogin(await fetch("/api/logs", { method: "DELETE" }));
    if (!response.ok) {
      throw new Error(await responseError(response, "清理日志失败"));
    }
    showToast("日志已清理");
    await loadLogs();
  } catch (error) {
    $("#logsMessage").textContent = error.message;
    $("#logsMessage").classList.add("error");
  } finally {
    button.disabled = false;
  }
}

function renderRules(rules) {
  const list = $("#rulesList");
  const empty = $("#rulesEmpty");
  const ruleCount = rules.reduce(
    (count, rule) => count
      + (rule.policy?.limit_bytes ? 1 : 0)
      + (rule.policy?.access_exists ? 1 : 0),
    0
  );
  $("#rulesCount").textContent = `${ruleCount} 条规则 · ${rules.length} 个对象`;
  list.hidden = !ruleCount;
  empty.hidden = Boolean(ruleCount);

  list.innerHTML = rules.map((rule) => {
    const policy = rule.policy || {};
    const targetRemoved = Boolean(rule.target_removed || policy.target_removed);
    const typeLabel = rule.target_type === "user" ? "用户" : "设备";
    const configuredRules = [];

    if (policy.limit_bytes) {
      const ratio = Math.min(100, (policy.usage_bytes / policy.limit_bytes) * 100);
      const enabled = policy.quota_enabled !== false;
      const blocked = Boolean(policy.quota_blocked);
      const stateLabel = targetRemoved
        ? "规则未生效"
        : !enabled
          ? "已停用"
          : blocked
            ? "已达到限额"
            : policy.bypassed
              ? "本月已解锁"
              : "监控中";
      const stateHint = targetRemoved
        ? "目标已移除"
        : !enabled
          ? "仅停用流量上限封禁"
          : blocked
            ? `使用率 ${ratio.toFixed(1)}%`
            : policy.bypassed
              ? "下月恢复执行"
              : `剩余 ${formatBytes(Math.max(0, policy.limit_bytes - policy.usage_bytes), true)}`;
      configuredRules.push(`
        <section class="rule-item quota-rule ${blocked ? "blocked" : ""} ${enabled ? "" : "disabled-rule"}">
          <div class="rule-kind">
            <b>流量上限封禁</b>
            <small>按月度用量自动执行</small>
          </div>
          <div class="rule-usage">
            <span>
              <small>本月用量</small>
              <b>${formatBytes(policy.usage_bytes, true)} / ${formatBytes(policy.limit_bytes, true)}</b>
            </span>
            <span class="rule-progress" aria-label="限额使用率 ${ratio.toFixed(1)}%">
              <i style="width:${ratio}%"></i>
            </span>
          </div>
          <div class="rule-state">
            <b>${stateLabel}</b>
            <span>${stateHint}</span>
          </div>
          ${ruleActions(rule, "quota", enabled, targetRemoved)}
        </section>
      `);
    }

    if (policy.access_exists) {
      const enabled = policy.access_enabled !== false;
      const active = Boolean(policy.access_active);
      const blocked = Boolean(policy.manual_blocked);
      const permanent = policy.block_mode === "permanent";
      const stateLabel = targetRemoved
        ? "规则未生效"
        : !enabled
          ? "已停用"
          : !active
            ? "已到期"
            : permanent
              ? "永久封禁中"
              : "临时封禁中";
      const stateHint = targetRemoved
        ? "目标已移除"
        : !enabled
          ? "仅停用手动封禁"
          : !active
            ? "可编辑后重新应用"
            : permanent
              ? "解除前持续生效"
              : `至 ${formatBlockUntil(policy.block_until)}`;
      configuredRules.push(`
        <section class="rule-item access-rule ${blocked ? "blocked" : ""} ${enabled ? "" : "disabled-rule"}">
          <div class="rule-kind">
            <b>手动封禁</b>
            <small>${permanent ? "永久模式" : "临时模式"}</small>
          </div>
          <div class="rule-config">
            <small>封禁方式</small>
            <b>${permanent ? "永久封禁" : `临时封禁至 ${formatBlockUntil(policy.block_until)}`}</b>
          </div>
          <div class="rule-state">
            <b>${stateLabel}</b>
            <span>${stateHint}</span>
          </div>
          ${ruleActions(rule, "access", enabled, targetRemoved)}
        </section>
      `);
    }

    return `
      <article class="rule-card rule-group ${rule.target_type} ${policy.blocked ? "blocked" : ""} ${targetRemoved ? "removed-target" : ""}">
        <header class="rule-group-header">
          <div class="rule-identity">
            <span class="rule-type">${typeLabel}</span>
            <span>
              <b>${escapeHtml(rule.target_name)}</b>
              <small>${escapeHtml(rule.subtitle)}</small>
            </span>
          </div>
          <span class="rule-group-count">${configuredRules.length} 条规则</span>
        </header>
        <div class="rule-items">${configuredRules.join("")}</div>
      </article>
    `;
  }).join("");

  list.querySelectorAll(".rule-edit-button").forEach((button) => {
    button.addEventListener("click", () => {
      const rule = state.rules.find(
        (item) => item.target_type === button.dataset.targetType
          && item.target_key === button.dataset.targetKey
      );
      if (rule) {
        openPolicy(
          rule.target_type,
          rule.target_key,
          rule.target_name,
          rule.policy,
          button.dataset.ruleType
        );
      }
    });
  });

  list.querySelectorAll(".rule-enabled-toggle").forEach((input) => {
    input.addEventListener("change", () => {
      const rule = state.rules.find(
        (item) => item.target_type === input.dataset.targetType
          && item.target_key === input.dataset.targetKey
      );
      if (rule) {
        toggleRuleEnabled(rule, input.dataset.ruleType, input.checked, input);
      }
    });
  });

  list.querySelectorAll(".rule-delete-button").forEach((button) => {
    button.addEventListener("click", () => {
      const rule = state.rules.find(
        (item) => item.target_type === button.dataset.targetType
          && item.target_key === button.dataset.targetKey
      );
      if (rule) deleteRuleItem(rule, button.dataset.ruleType, button);
    });
  });
}

function ruleActions(rule, ruleType, enabled, targetRemoved) {
  const typeName = ruleType === "quota" ? "流量上限封禁" : "手动封禁";
  return `
    <div class="rule-actions">
      <label class="rule-toggle" title="${targetRemoved ? "目标已移除，无法更改规则状态" : enabled ? `停用${typeName}` : `启用${typeName}`}">
        <input
          class="rule-enabled-toggle"
          type="checkbox"
          data-target-type="${escapeHtml(rule.target_type)}"
          data-target-key="${escapeHtml(rule.target_key)}"
          data-rule-type="${ruleType}"
          ${enabled ? "checked" : ""}
          ${targetRemoved ? "disabled" : ""}
        >
        <span class="rule-toggle-track" aria-hidden="true"></span>
        <em>${enabled ? "已启用" : "已停用"}</em>
      </label>
      <button
        class="rule-edit-button"
        type="button"
        data-target-type="${escapeHtml(rule.target_type)}"
        data-target-key="${escapeHtml(rule.target_key)}"
        data-rule-type="${ruleType}"
        ${targetRemoved ? "disabled title=\"目标已移除，无法编辑规则\"" : ""}
      >编辑</button>
      <button
        class="rule-delete-button"
        type="button"
        data-target-type="${escapeHtml(rule.target_type)}"
        data-target-key="${escapeHtml(rule.target_key)}"
        data-rule-type="${ruleType}"
      >删除</button>
    </div>
  `;
}

async function toggleRuleEnabled(rule, ruleType, enabled, input) {
  input.disabled = true;
  const typeName = ruleType === "quota" ? "流量上限封禁" : "手动封禁";
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${rule.target_type}/${encodeURIComponent(rule.target_key)}/${ruleType}/enabled`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled }),
        }
      )
    );
    if (!response.ok) {
      throw new Error(await policyError(response, "更新规则状态失败"));
    }
    showToast(`${typeName}已${enabled ? "启用" : "停用"}`);
    await Promise.all([loadRules(), loadDashboard()]);
  } catch (error) {
    input.checked = !enabled;
    input.disabled = false;
    showToast(error.message);
  }
}

async function deleteRuleItem(rule, ruleType, button) {
  const typeName = ruleType === "quota" ? "流量上限封禁" : "手动封禁";
  if (!window.confirm(`确定删除 ${rule.target_name} 的${typeName}吗？`)) return;
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${rule.target_type}/${encodeURIComponent(rule.target_key)}${ruleType === "access" ? "/block" : ""}`,
        { method: "DELETE" }
      )
    );
    if (!response.ok) {
      throw new Error(await policyError(response, "删除规则失败"));
    }
    showToast(`${typeName}已删除`);
    await Promise.all([loadRules(), loadDashboard()]);
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
}

async function loadRules() {
  try {
    const response = requireLogin(await fetch("/api/policies"));
    if (!response.ok) throw new Error("读取规则失败");
    const payload = await response.json();
    state.rules = payload.rules || [];
    renderRules(state.rules);
  } catch (error) {
    showToast(error.message);
  }
}

function renderUsers(users, total) {
  const list = $("#usersList");
  const empty = $("#emptyState");
  const tailnetCount = users.filter((user) => user.network_scope === "tailnet").length;
  const externalCount = users.filter((user) => user.network_scope === "external").length;
  $("#userCount").textContent = `${users.length} 位 · 外部 ${externalCount} / 本网 ${tailnetCount}`;

  if (!users.length) {
    list.innerHTML = "";
    list.hidden = true;
    empty.hidden = false;
    return;
  }

  list.hidden = false;
  empty.hidden = true;
  const periodLabel = usagePeriodLabel();
  list.innerHTML = users.map((user) => {
    const share = total ? (user.total / total) * 100 : 0;
    const scope = user.network_scope === "tailnet"
      ? { label: "本 Tailnet", className: "tailnet" }
      : user.network_scope === "external"
        ? { label: "外部分享", className: "external" }
        : { label: "未识别", className: "unknown" };
    const devices = user.device_items || [];
    const deviceTotal = devices.reduce(
      (sum, device) => sum + Number(device.total || 0),
      0
    );
    const unassignedTotal = Math.max(0, user.total - deviceTotal);
    const expanded = state.expandedUsers.has(user.key);
    return `
      <article class="exit-user-card ${user.removed ? "removed-user" : ""}">
        <header class="exit-user-header">
          <button
            type="button"
            class="user-expand-button"
            data-user-key="${escapeHtml(user.key)}"
            aria-expanded="${expanded}"
            aria-label="${expanded ? "收起" : "展开"} ${escapeHtml(user.name)} 的设备列表"
            title="${expanded ? "收起设备列表" : "展开设备列表"}"
          ><span aria-hidden="true">▶</span></button>
          <div class="exit-user-identity">
            <div class="person">
              <span class="avatar">${escapeHtml(initials(user.name))}</span>
              <span class="person-copy">
                <b>${escapeHtml(user.name)}</b>
                <span>${escapeHtml(user.login_name || user.key)}</span>
              </span>
            </div>
            <div class="exit-user-labels">
              <span class="device-count"><i class="online-dot ${user.online ? "on" : ""}"></i>${devices.length} 台设备</span>
              <span class="scope-badge ${scope.className}">${scope.label}</span>
              ${user.removed ? '<span class="removed-user-badge">用户已移除</span>' : ""}
              ${policyBadges(user.policy)}
              ${partialDevicePolicyBadges(user.policy, devices)}
            </div>
          </div>
          <div class="exit-user-actions">
            <button
              type="button"
              class="user-websites-button"
              data-user-key="${escapeHtml(user.key)}"
            >用户访问记录</button>
            <button
              type="button"
              class="user-alias-button"
              data-user-key="${escapeHtml(user.key)}"
            >修改备注</button>
            <button
              type="button"
              class="user-policy-inline-button ${hasPolicyRule(user.policy) ? "has-rule" : ""}"
              data-user-key="${escapeHtml(user.key)}"
              title="${escapeHtml(policySummary(user.policy))}"
            >设置规则</button>
          </div>
        </header>

        <div class="user-usage-summary">
          <div><span>下载 · ${periodLabel}</span><strong>${formatUsagePair(user.recent_24h_download, user.download)}</strong></div>
          <div><span>上传 · ${periodLabel}</span><strong>${formatUsagePair(user.recent_24h_upload, user.upload)}</strong></div>
          <div><span>用户总计 · ${periodLabel}</span><strong>${formatUsagePair(user.recent_24h_total, user.total)}</strong></div>
          <div>
            <span>占全部出口流量</span>
            <strong>${share.toFixed(1)}%</strong>
            <span class="user-share-track"><i style="width:${Math.min(100, share)}%"></i></span>
          </div>
        </div>

        <div class="user-devices-details" ${expanded ? "" : "hidden"}>
          <div class="user-devices-heading">
            <div class="user-devices-heading-copy">
              <span>所属设备与用量</span>
              ${unassignedTotal > 0
                ? `<small>未归属流量 ${formatBytes(unassignedTotal, true)}</small>`
                : ""}
            </div>
            <div class="device-column-labels" aria-hidden="true">
              <span>下载<small>${periodLabel}</small></span>
              <span>上传<small>${periodLabel}</small></span>
              <span>总计<small>${periodLabel}</small></span>
            </div>
            <span class="device-action-spacer" aria-hidden="true"></span>
          </div>
          <div class="inline-device-list">
            ${devices.length ? devices.map((device) => `
              <article class="inline-device">
                <div class="inline-device-identity">
                  <div class="inline-device-title">
                    <b><i class="online-dot ${device.online ? "on" : ""}"></i>${escapeHtml(device.device_name || "未知设备")}</b>
                    ${device.expired ? '<span class="expired-device-badge">Expired</span>' : ""}
                    <span class="device-os-badge">${escapeHtml(device.os_name || "未知系统")}</span>
                    ${policyBadges(device.policy)}
                  </div>
                  <div class="inline-device-addresses">
                    ${(device.addresses || []).map((address) => `
                      <small><em>IPv${address.family}</em>${escapeHtml(address.ip)}</small>
                    `).join("")}
                  </div>
                </div>
                <div class="inline-device-traffic">
                  <span aria-label="下载，${periodLabel} ${formatUsagePair(device.recent_24h_download, device.download)}"><b>${formatUsagePair(device.recent_24h_download, device.download)}</b></span>
                  <span aria-label="上传，${periodLabel} ${formatUsagePair(device.recent_24h_upload, device.upload)}"><b>${formatUsagePair(device.recent_24h_upload, device.upload)}</b></span>
                  <span aria-label="总计，${periodLabel} ${formatUsagePair(device.recent_24h_total, device.total)}"><b>${formatUsagePair(device.recent_24h_total, device.total)}</b></span>
                </div>
                <div class="inline-device-actions">
                  <button
                    type="button"
                    class="inline-device-websites-button"
                    data-user-key="${escapeHtml(user.key)}"
                    data-device-id="${escapeHtml(device.device_id)}"
                  >访问记录</button>
                  <button
                    type="button"
                    class="device-alias-button"
                    data-user-key="${escapeHtml(user.key)}"
                    data-device-id="${escapeHtml(device.device_id)}"
                  >修改备注</button>
                  <button
                    type="button"
                    class="inline-device-policy-button ${hasPolicyRule(device.policy) ? "has-rule" : ""}"
                    data-user-key="${escapeHtml(user.key)}"
                    data-device-id="${escapeHtml(device.device_id)}"
                    title="${escapeHtml(policySummary(device.policy))}"
                  >设置规则</button>
                </div>
              </article>
            `).join("") : '<div class="no-devices">暂无关联设备</div>'}
          </div>
        </div>
      </article>
    `;
  }).join("");

  list.querySelectorAll(".user-expand-button").forEach((button) => {
    button.addEventListener("click", () => {
      const userKey = button.dataset.userKey;
      if (state.expandedUsers.has(userKey)) {
        state.expandedUsers.delete(userKey);
      } else {
        state.expandedUsers.add(userKey);
      }
      renderUsers(
        state.payload?.users || [],
        state.payload?.summary?.total || 0
      );
    });
  });
  list.querySelectorAll(".user-alias-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      if (user) openUserAliasDialog(user);
    });
  });
  list.querySelectorAll(".device-alias-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      const device = user?.device_items?.find(
        (item) => item.device_id === button.dataset.deviceId
      );
      if (device) openDeviceAliasDialog(device, user);
    });
  });
  list.querySelectorAll(".user-policy-inline-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      if (user) openPolicy("user", user.key, user.name, user.policy);
    });
  });
  list.querySelectorAll(".inline-device-policy-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      const device = user?.device_items?.find(
        (item) => item.device_id === button.dataset.deviceId
      );
      if (device) {
        openPolicy("device", device.device_id, device.device_name, device.policy);
      }
    });
  });
  list.querySelectorAll(".inline-device-websites-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      const device = user?.device_items?.find(
        (item) => item.device_id === button.dataset.deviceId
      );
      if (device) {
        openWebsiteDetails("device", device.device_id, device.device_name);
      }
    });
  });
  list.querySelectorAll(".user-websites-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      if (user) openWebsiteDetails("user", user.key, user.name);
    });
  });
}

function chartUnit(maxValue) {
  const units = [
    { value: 1_000_000_000_000, suffix: "TB" },
    { value: 1_000_000_000, suffix: "GB" },
    { value: 1_000_000, suffix: "MB" },
    { value: 1_000, suffix: "KB" },
  ];
  return units.find((unit) => maxValue >= unit.value) || { value: 1, suffix: "B" };
}

function drawChart() {
  if (!state.payload || !chart) return;
  const daily = state.payload.daily;
  const rect = chart.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  chart.width = Math.max(1, Math.round(rect.width * dpr));
  chart.height = Math.max(1, Math.round(rect.height * dpr));
  const ctx = chart.getContext("2d");
  ctx.scale(dpr, dpr);

  const width = rect.width;
  const height = rect.height;
  const padding = { top: 8, right: 2, bottom: 34, left: 72 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maxRaw = Math.max(1, ...daily.map((item) => item.upload + item.download));
  const max = maxRaw * 1.14;
  const unit = chartUnit(max);

  ctx.clearRect(0, 0, width, height);
  ctx.font = '14px Inter, "PingFang SC", sans-serif';
  ctx.textBaseline = "middle";

  for (let line = 0; line <= 4; line += 1) {
    const y = padding.top + (plotHeight / 4) * line;
    ctx.strokeStyle = "rgba(140, 153, 148, 0.13)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding.left, y + 0.5);
    ctx.lineTo(width, y + 0.5);
    ctx.stroke();

    const labelValue = max * (1 - line / 4) / unit.value;
    ctx.fillStyle = "#6f7b76";
    ctx.textAlign = "right";
    ctx.fillText(`${labelValue.toFixed(labelValue >= 10 ? 0 : 1)} ${unit.suffix}`, padding.left - 9, y);
  }

  const slot = plotWidth / Math.max(1, daily.length);
  const barWidth = Math.max(3, Math.min(14, slot * 0.56));
  state.chartBars = [];

  daily.forEach((item, index) => {
    const x = padding.left + slot * index + (slot - barWidth) / 2;
    const uploadHeight = (item.upload / max) * plotHeight;
    const downloadHeight = (item.download / max) * plotHeight;
    const bottom = padding.top + plotHeight;

    ctx.fillStyle = "#70dcc2";
    roundTopRect(ctx, x, bottom - downloadHeight - uploadHeight, barWidth, downloadHeight + uploadHeight, 3);
    ctx.fill();

    if (uploadHeight > 0) {
      ctx.fillStyle = "#ff956f";
      ctx.fillRect(x, bottom - uploadHeight, barWidth, uploadHeight);
    }

    state.chartBars.push({ x, width: barWidth, item });

    const showEvery = width < 600 ? Math.ceil(daily.length / 6) : Math.ceil(daily.length / 10);
    if (index % showEvery === 0 || index === daily.length - 1) {
      ctx.fillStyle = "#6f7b76";
      ctx.textAlign = "center";
      const date = new Date(`${item.day}T00:00:00`);
      ctx.fillText(`${date.getMonth() + 1}/${date.getDate()}`, x + barWidth / 2, height - 10);
    }
  });
}

function roundTopRect(ctx, x, y, width, height, radius) {
  if (height <= 0) {
    ctx.beginPath();
    return;
  }
  const r = Math.min(radius, width / 2, height);
  ctx.beginPath();
  ctx.moveTo(x, y + height);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.lineTo(x + width - r, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + r);
  ctx.lineTo(x + width, y + height);
  ctx.closePath();
}

function handleChartPointer(event) {
  const rect = chart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const closest = state.chartBars.reduce((best, bar) => (
    !best || Math.abs(x - (bar.x + bar.width / 2)) < Math.abs(x - (best.x + best.width / 2))
      ? bar
      : best
  ), null);

  if (!closest || Math.abs(x - (closest.x + closest.width / 2)) > 24) {
    tooltip.hidden = true;
    return;
  }
  const date = new Date(`${closest.item.day}T00:00:00`);
  tooltip.innerHTML = `
    <b>${date.toLocaleDateString("zh-CN", { month: "long", day: "numeric" })}</b>
    下载 ${formatBytes(closest.item.download)}<br>
    上传 ${formatBytes(closest.item.upload)}
  `;
  tooltip.style.left = `${closest.x + closest.width / 2}px`;
  tooltip.style.top = `${Math.max(62, event.clientY - rect.top)}px`;
  tooltip.hidden = false;
}

function openUserAliasDialog(user) {
  state.selectedAliasTarget = {
    type: "user",
    key: user.key,
  };
  $("#dialogTitle").textContent = `${user.name} · 修改备注`;
  $("#aliasInput").value = String(user.name || "").trim();
  $("#aliasInput").placeholder = "例如：小林";
  $("#saveAlias").disabled = false;
  $("#userDialog").showModal();
}

function openDeviceAliasDialog(device, user) {
  const existingAlias = String(device.alias || "").trim();
  const userAlias = String(user?.alias || user?.name || "").trim();
  const suggestedAlias = userAlias ? `${userAlias.slice(0, 78)}'s` : "";
  state.selectedAliasTarget = {
    type: "device",
    key: device.device_id,
  };
  $("#dialogTitle").textContent = `${device.device_name} · 修改备注`;
  $("#aliasInput").value = existingAlias || suggestedAlias;
  $("#aliasInput").placeholder = "例如：小林的手机；留空恢复默认名称";
  $("#saveAlias").disabled = false;
  $("#userDialog").showModal();
}

function localDay() {
  const now = new Date();
  return [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, "0"),
    String(now.getDate()).padStart(2, "0"),
  ].join("-");
}

function websiteTime(value, includeDate = false) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return value;
  const options = {
    hour: "2-digit",
    minute: "2-digit",
  };
  if (includeDate) {
    options.month = "2-digit";
    options.day = "2-digit";
  }
  return parsed.toLocaleString("zh-CN", options);
}

function setWebsitePeriod(period, load = true) {
  state.activeWebsitePeriod = period === "day" ? "day" : "24h";
  document.querySelectorAll("[data-website-period]").forEach((button) => {
    const active = button.dataset.websitePeriod === state.activeWebsitePeriod;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  $("#websiteDayField").hidden = state.activeWebsitePeriod !== "day";
  if (load && state.activeWebsiteTarget) loadWebsiteDetails();
}

async function loadWebsiteDetails() {
  const target = state.activeWebsiteTarget;
  const day = $("#websiteDay").value;
  const period = state.activeWebsitePeriod;
  const list = $("#websiteList");
  if (!target || (period === "day" && !day)) return;
  list.innerHTML = `<div class="website-loading">正在读取${period === "24h" ? "过去1天" : "当天"}网站统计…</div>`;
  try {
    const targetPath = target.type === "user"
      ? `/api/users/${encodeURIComponent(target.key)}/websites`
      : `/api/devices/${encodeURIComponent(target.key)}/websites`;
    const params = new URLSearchParams({ period });
    if (period === "day") params.set("day", day);
    const response = requireLogin(
      await fetch(`${targetPath}?${params}`)
    );
    if (!response.ok) throw new Error("读取网站统计失败");
    const payload = await response.json();
    const summary = payload.summary || {};
    $("#websiteDestinations").textContent = `${summary.destinations || 0}`;
    $("#websiteVisits").textContent = `${summary.visits || 0}`;
    $("#websiteTraffic").textContent = formatBytes(summary.total, true);
    const tracking = payload.tracking || {};
    const aggregationNote = target.type === "user"
      ? `已聚合该用户 ${payload.device_count || 0} 台设备。`
      : "";
    const periodNote = payload.period === "24h"
      ? "当前为滚动过去1天，不受面板统计时区影响；访问时间按当前浏览器时区显示。"
      : `当前按 ${payload.timezone || "面板设置"} 的自然日统计；访问时间按当前浏览器时区显示。`;
    $("#websiteTrackingNote").textContent = tracking.error
      ? tracking.error
      : `${aggregationNote}${periodNote}`;

    const websites = payload.websites || [];
    const includeDate = payload.period === "24h";
    list.innerHTML = websites.length
      ? websites.map((item) => `
        <article class="website-row">
          <div class="website-destination">
            <b>${escapeHtml(item.destination)}</b>
            <small>${websiteTime(item.first_seen, includeDate)} – ${websiteTime(item.last_seen, includeDate)}</small>
          </div>
          <span><small>访问</small><b>${item.visits} 次</b></span>
          <span><small>下载</small><b>${formatBytes(item.download, true)}</b></span>
          <span><small>上传</small><b>${formatBytes(item.upload, true)}</b></span>
          <span><small>总计</small><b>${formatBytes(item.total, true)}</b></span>
        </article>
      `).join("")
      : `<div class="website-empty">${period === "24h" ? "过去1天" : "这一天"}还没有识别到网站访问记录。</div>`;
  } catch (error) {
    list.innerHTML = `<div class="website-empty">${escapeHtml(error.message)}</div>`;
  }
}

function openWebsiteDetails(type, key, name) {
  state.activeWebsiteTarget = { type, key, name };
  $("#websiteTitle").textContent = type === "user"
    ? `${name} · 用户访问记录`
    : `${name} · 设备访问记录`;
  const dayInput = $("#websiteDay");
  dayInput.max = localDay();
  dayInput.value = localDay();
  setWebsitePeriod("24h", false);
  $("#websiteDialog").showModal();
  loadWebsiteDetails();
}

function openPolicy(targetType, targetKey, targetName, policy, initialRule = null) {
  state.activePolicyTarget = {
    targetType,
    targetKey,
    targetName,
    policy,
  };
  const singleRuleMode = initialRule === "quota" || initialRule === "access";
  const policyDialog = $("#policyDialog");
  policyDialog.classList.toggle("single-rule-mode", singleRuleMode);
  $("#policyTitle").textContent = singleRuleMode
    ? `${targetName} · ${initialRule === "quota" ? "编辑流量上限" : "编辑手动封禁"}`
    : targetType === "user"
      ? `${targetName} · 用户规则`
      : `${targetName} · 设备规则`;
  $("#policyUsage").textContent = formatBytes(policy?.usage_bytes || 0, true);

  const status = $("#policyStatus");
  status.className = "";
  if (!policy?.limit_bytes) {
    status.textContent = "尚未设置流量上限封禁";
  } else if (policy.quota_enabled === false) {
    status.textContent = "流量上限封禁已停用，可在规则页面重新启用";
    status.classList.add("bypassed");
  } else if (policy.quota_blocked) {
    status.textContent = "已达到月度上限，当前已封锁";
    status.classList.add("blocked");
  } else if (policy.bypassed) {
    status.textContent = "本月已手动解锁，次月重新执行该规则";
    status.classList.add("bypassed");
  } else {
    status.textContent = `监控中 · 上限 ${formatBytes(policy.limit_bytes, true)}`;
  }

  const limit = formatLimitInput(policy?.limit_bytes);
  $("#policyLimitValue").value = limit.value;
  $("#policyLimitUnit").value = limit.unit;
  $("#deletePolicy").hidden = !policy?.limit_bytes;
  $("#unlockPolicy").hidden = !policy?.quota_blocked;
  $("#policyEnforcementNote").textContent =
    "达到上限后将同时封锁该目标的 IPv4 和 IPv6；下月用量归零后自动解除。";

  const accessExists = Boolean(policy?.access_exists);
  const accessActive = Boolean(policy?.access_active);
  const accessBlocked = Boolean(policy?.manual_blocked);
  const permanent = accessExists && policy.block_mode === "permanent";
  const accessStatus = $("#accessBlockStatus");
  accessStatus.className = accessBlocked ? "blocked" : "";
  accessStatus.textContent = !accessExists
    ? "尚未设置"
    : policy.access_enabled === false
      ? "手动封禁已停用"
      : !accessActive
        ? "临时封禁已到期"
        : permanent
          ? "永久封禁中"
          : "临时封禁中";
  $("#accessBlockHint").textContent = !accessExists
    ? "选择封禁方式并应用规则"
    : policy.access_enabled === false
      ? "可在规则页面单独重新启用"
      : !accessActive
        ? "编辑时长后可重新应用"
        : permanent
          ? "当前持续封禁，手动解除后恢复"
          : `封禁至 ${formatBlockUntil(policy.block_until)}`;

  $("#blockDurationValue").value = "24";
  $("#blockDurationUnit").value = "hours";
  $("#removeAccessBlock").hidden = !accessExists;
  $("#accessBlockNote").textContent =
    "封禁会同时阻止目标的 IPv4 和 IPv6 出口流量。";

  selectAccessBlockMode(permanent ? "permanent" : "temporary");
  const selectedPolicyRule = initialRule === "access" ? "manual" : initialRule;
  selectPolicyRule(selectedPolicyRule || (accessExists ? "manual" : "quota"));
  policyDialog.showModal();
}

async function policyError(response, fallback) {
  try {
    const payload = await response.json();
    return payload.detail || fallback;
  } catch {
    return fallback;
  }
}

async function refreshAfterPolicyChange(message) {
  $("#policyDialog").close();
  showToast(message);
  await loadDashboard();
  if (state.currentPage === "rules") {
    await loadRules();
  }
}

async function savePolicy() {
  const target = state.activePolicyTarget;
  const input = Number($("#policyLimitValue").value);
  if (!target || !Number.isFinite(input) || input <= 0) {
    showToast("请输入大于 0 的流量上限");
    return;
  }
  const multiplier = $("#policyLimitUnit").value === "TB"
    ? 1_000_000_000_000
    : 1_000_000_000;
  const button = $("#savePolicy");
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${target.targetType}/${encodeURIComponent(target.targetKey)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            monthly_limit_bytes: Math.round(input * multiplier),
          }),
        }
      )
    );
    if (!response.ok) throw new Error(await policyError(response, "保存规则失败"));
    await refreshAfterPolicyChange("流量上限封禁已保存");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function deletePolicy() {
  const target = state.activePolicyTarget;
  if (!target) return;
  const button = $("#deletePolicy");
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${target.targetType}/${encodeURIComponent(target.targetKey)}`,
        { method: "DELETE" }
      )
    );
    if (!response.ok) throw new Error(await policyError(response, "删除规则失败"));
    await refreshAfterPolicyChange("流量上限封禁已删除");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function unlockPolicy() {
  const target = state.activePolicyTarget;
  if (!target) return;
  const button = $("#unlockPolicy");
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${target.targetType}/${encodeURIComponent(target.targetKey)}/unlock`,
        { method: "POST" }
      )
    );
    if (!response.ok) throw new Error(await policyError(response, "手动解锁失败"));
    await refreshAfterPolicyChange("本月已手动解锁");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function setAccessBlock(permanent) {
  const target = state.activePolicyTarget;
  if (!target) return;
  const button = $("#saveAccessBlock");
  const duration = Number($("#blockDurationValue").value);
  const multipliers = {
    minutes: 60,
    hours: 3600,
    days: 86400,
  };
  if (!permanent && (!Number.isFinite(duration) || duration <= 0)) {
    showToast("请输入大于 0 的临时封禁时长");
    return;
  }
  const durationSeconds = permanent
    ? null
    : Math.round(duration * multipliers[$("#blockDurationUnit").value]);
  if (!permanent && durationSeconds > 31_536_000) {
    showToast("临时封禁最长为 365 天");
    return;
  }
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${target.targetType}/${encodeURIComponent(target.targetKey)}/block`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(
            permanent
              ? { permanent: true }
              : { duration_seconds: durationSeconds }
          ),
        }
      )
    );
    if (!response.ok) {
      throw new Error(await policyError(response, "设置封禁失败"));
    }
    await refreshAfterPolicyChange(permanent ? "已永久封禁" : "临时封禁已生效");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function removeAccessBlock(button) {
  const target = state.activePolicyTarget;
  if (!target) return;
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/policies/${target.targetType}/${encodeURIComponent(target.targetKey)}/block`,
        { method: "DELETE" }
      )
    );
    if (!response.ok) {
      throw new Error(await policyError(response, "解除封禁失败"));
    }
    await refreshAfterPolicyChange("手动封禁已解除");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function saveAlias() {
  const target = state.selectedAliasTarget;
  if (!target) return;
  const alias = $("#aliasInput").value.trim();
  const button = $("#saveAlias");
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(
        `/api/${target.type === "device" ? "devices" : "users"}/${encodeURIComponent(target.key)}`,
        {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias }),
        }
      )
    );
    if (!response.ok) throw new Error("保存失败");
    showToast(target.type === "device" ? "设备备注已保存" : "用户备注已保存");
    $("#userDialog").close();
    state.selectedAliasTarget = null;
    await loadDashboard();
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  const button = $("#logoutButton");
  button.disabled = true;
  try {
    await fetch("/api/logout", { method: "POST" });
  } finally {
    window.location.replace("/login");
  }
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    toast.hidden = true;
  }, 2200);
}

async function loadDashboard() {
  try {
    const month = monthPicker.value;
    const params = new URLSearchParams();
    if (month) params.set("month", month);
    if ($("#showExpiredDevices").checked) {
      params.set("show_expired", "true");
    }
    const query = params.toString();
    const response = requireLogin(
      await fetch(`/api/dashboard${query ? `?${query}` : ""}`)
    );
    if (!response.ok) throw new Error(`面板接口返回 ${response.status}`);
    const payload = await response.json();
    state.payload = payload;
    setPanelTimezone(payload.timezone);
    monthPicker.value = payload.month;
    updateMonthReset();
    renderSummary(payload.summary);
    renderUsers(payload.users, payload.summary.total);
    setCollectorStatus(
      payload.collector,
      payload.last_collect,
      payload.dashboard_uptime_seconds
    );
    $("#projectVersion").textContent = payload.version || "unknown";
    renderRecentLogs(payload.recent_logs || []);
    if (state.currentPage === "overview") drawChart();
  } catch (error) {
    const status = $("#collectorStatus");
    status.classList.add("error");
    $("#collectorStatusText").textContent = "面板异常";
    status.title = error.message;
    showToast(error.message);
  }
}

function setupDialogInteractions() {
  document.querySelectorAll("dialog").forEach((dialog) => {
    let backdropPointerId = null;
    const isBackdropPointer = (event) => {
      if (event.target !== dialog) return false;
      const bounds = dialog.getBoundingClientRect();
      const inside = event.clientX >= bounds.left
        && event.clientX <= bounds.right
        && event.clientY >= bounds.top
        && event.clientY <= bounds.bottom;
      return !inside;
    };

    dialog.addEventListener("pointerdown", (event) => {
      backdropPointerId = isBackdropPointer(event) ? event.pointerId : null;
    });

    dialog.addEventListener("pointerup", (event) => {
      const completedBackdropClick = backdropPointerId === event.pointerId
        && isBackdropPointer(event);
      backdropPointerId = null;
      if (completedBackdropClick) dialog.close();
    });

    dialog.addEventListener("pointercancel", () => {
      backdropPointerId = null;
    });

    dialog.addEventListener("close", () => {
      backdropPointerId = null;
    });

    dialog.addEventListener("keydown", (event) => {
      if (
        event.key !== "Enter"
        || event.isComposing
        || event.ctrlKey
        || event.altKey
        || event.metaKey
        || event.shiftKey
        || event.target.closest("button")
      ) {
        return;
      }

      if (dialog.id === "userDialog") return;

      if (dialog.id === "websiteDialog") {
        event.preventDefault();
        loadWebsiteDetails();
      } else if (dialog.id === "policyDialog") {
        if (event.target.closest("select")) return;
        event.preventDefault();
        submitSelectedPolicyRule();
      }
    });
  });
}

monthPicker.addEventListener("change", () => {
  updateMonthReset();
  loadDashboard();
});
$("#resetMonth").addEventListener("click", () => {
  monthPicker.value = currentMonth();
  updateMonthReset();
  loadDashboard();
});
$("#showExpiredDevices").addEventListener("change", loadDashboard);
$("#aliasForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!$("#saveAlias").disabled) saveAlias();
});
$("#aliasInput").addEventListener("keydown", (event) => {
  if (
    event.key !== "Enter"
    || event.isComposing
    || event.ctrlKey
    || event.altKey
    || event.metaKey
    || event.shiftKey
  ) {
    return;
  }
  event.preventDefault();
  if (!$("#saveAlias").disabled) saveAlias();
});
$("#userDialog .close-button").addEventListener("click", () => {
  $("#userDialog").close("cancel");
});
$("#websiteDay").addEventListener("change", () => {
  if (state.activeWebsitePeriod === "day") loadWebsiteDetails();
});
document.querySelectorAll("[data-website-period]").forEach((button) => {
  button.addEventListener("click", () => {
    setWebsitePeriod(button.dataset.websitePeriod);
  });
});
$("#savePolicy").addEventListener("click", savePolicy);
$("#deletePolicy").addEventListener("click", deletePolicy);
$("#unlockPolicy").addEventListener("click", unlockPolicy);
const policyRuleButtons = [...document.querySelectorAll("[data-policy-rule]")];
policyRuleButtons.forEach((button, index) => {
  button.addEventListener("click", () => {
    selectPolicyRule(button.dataset.policyRule);
  });
  button.addEventListener("keydown", (event) => {
    const directions = {
      ArrowLeft: -1,
      ArrowUp: -1,
      ArrowRight: 1,
      ArrowDown: 1,
    };
    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      const target = event.key === "Home"
        ? policyRuleButtons[0]
        : policyRuleButtons.at(-1);
      selectPolicyRule(target.dataset.policyRule);
      target.focus();
      return;
    }
    if (!directions[event.key]) return;
    event.preventDefault();
    const nextIndex = (index + directions[event.key] + policyRuleButtons.length)
      % policyRuleButtons.length;
    const target = policyRuleButtons[nextIndex];
    selectPolicyRule(target.dataset.policyRule);
    target.focus();
  });
});
const accessBlockModeButtons = [
  ...document.querySelectorAll("[data-access-block-mode]"),
];
accessBlockModeButtons.forEach((button, index) => {
  button.addEventListener("click", () => {
    selectAccessBlockMode(button.dataset.accessBlockMode);
  });
  button.addEventListener("keydown", (event) => {
    const direction = event.key === "ArrowLeft" || event.key === "ArrowUp"
      ? -1
      : event.key === "ArrowRight" || event.key === "ArrowDown"
        ? 1
        : 0;
    if (!direction) return;
    event.preventDefault();
    const target = accessBlockModeButtons[
      (index + direction + accessBlockModeButtons.length)
        % accessBlockModeButtons.length
    ];
    selectAccessBlockMode(target.dataset.accessBlockMode);
    target.focus();
  });
});
$("#saveAccessBlock").addEventListener("click", () => {
  setAccessBlock(state.activeAccessBlockMode === "permanent");
});
$("#removeAccessBlock").addEventListener("click", (event) => {
  removeAccessBlock(event.currentTarget);
});
$("#logoutButton").addEventListener("click", logout);
$("#logoutAllDevices").addEventListener("click", logoutAllDevices);
$("#refreshLogs").addEventListener("click", loadLogs);
$("#clearLogs").addEventListener("click", clearLogs);
$("#logDate").addEventListener("change", loadLogs);
$("#logKeyword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") loadLogs();
});
$("#configForm").addEventListener("submit", saveSettings);
$("#passwordForm").addEventListener("submit", changePanelPassword);
chart.addEventListener("pointermove", handleChartPointer);
chart.addEventListener("pointerleave", () => { tooltip.hidden = true; });
window.addEventListener("resize", drawChart);
window.addEventListener("hashchange", () => {
  showPage(pageFromHash());
});

setupDialogInteractions();
showPage(pageFromHash());
loadDashboard();
window.setInterval(() => {
  loadDashboard();
  if (state.currentPage === "logs") loadLogs();
}, 30_000);
window.setInterval(updatePanelTimezoneClock, 1_000);
