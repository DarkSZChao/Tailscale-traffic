const state = {
  payload: null,
  selectedUser: null,
  activePolicyTarget: null,
  enforcementSupported: false,
  chartBars: [],
  currentPage: "overview",
  rules: [],
};

const $ = (selector) => document.querySelector(selector);
const monthPicker = $("#monthPicker");
const chart = $("#usageChart");
const tooltip = $("#chartTooltip");
const PAGE_META = {
  overview: {
    eyebrow: "EXIT NODE / OVERVIEW",
    title: "流量概览",
    description: "查看当月总流量、来源构成与每日趋势。",
    usesMonth: true,
  },
  users: {
    eyebrow: "EXIT ACCESS / DEVICES",
    title: "出口控制",
    description: "纵向查看每位用户及其所属设备的实际用量，并直接管理流量上限。",
    usesMonth: true,
  },
  rules: {
    eyebrow: "MONTHLY QUOTA / POLICIES",
    title: "限额规则",
    description: "集中管理用户和设备的月度上限、封锁与手动解锁状态。",
    usesMonth: false,
  },
  system: {
    eyebrow: "COLLECTOR / RUNTIME",
    title: "系统状态",
    description: "检查采集方式、规则执行能力和本机数据存储状态。",
    usesMonth: false,
  },
};

function pageFromHash() {
  const page = window.location.hash.slice(1);
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
  } else if (selectedPage === "system" && state.payload) {
    renderSystem(state.payload);
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

function policyBadge(policy, enforcementSupported) {
  if (!policy?.limit_bytes) return "";
  if (policy.blocked) {
    return `<span class="quota-badge blocked">${enforcementSupported ? "已封锁" : "已超限"}</span>`;
  }
  if (policy.bypassed) {
    return '<span class="quota-badge bypassed">本月已解锁</span>';
  }
  return '<span class="quota-badge">有限额</span>';
}

function policySummary(policy, enforcementSupported) {
  if (!policy?.limit_bytes) return "未设置";
  if (policy.blocked) return enforcementSupported ? "已封锁" : "已超限";
  if (policy.bypassed) return "本月已解锁";
  return `${formatBytes(policy.usage_bytes, true)} / ${formatBytes(policy.limit_bytes, true)}`;
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

function setCollectorStatus(collector, lastCollect) {
  const status = $("#collectorStatus");
  const healthy = Boolean(collector?.healthy);
  status.classList.toggle("error", !healthy);
  status.innerHTML = `<span class="status-dot"></span>${healthy ? "采集正常" : "采集异常"}`;
  status.title = collector?.error || "";
  $("#lastCollect").textContent = `更新于 ${formatTime(lastCollect)}`;
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

function renderSystem(payload) {
  if (!payload) return;
  const modeLabels = {
    demo: "演示数据",
    "linux-firewall": "Linux 防火墙",
    "windows-capture": "Windows 抓包",
  };
  const collector = payload.collector || {};
  $("#systemCollectorMode").textContent = modeLabels[collector.mode] || collector.mode || "未知";
  $("#systemEnforcement").textContent = collector.enforcement_supported
    ? "支持自动封锁"
    : "仅显示超限";
  $("#systemInterval").textContent = collector.interval
    ? `${collector.interval} 秒`
    : "—";
  $("#systemLastCollect").textContent = formatTime(payload.last_collect);
  $("#systemQuota").textContent = payload.summary?.quota
    ? formatBytes(payload.summary.quota, true)
    : "未设置";
}

function renderRules(rules) {
  const list = $("#rulesList");
  const empty = $("#rulesEmpty");
  $("#rulesCount").textContent = `${rules.length} 条规则`;
  list.hidden = !rules.length;
  empty.hidden = Boolean(rules.length);

  list.innerHTML = rules.map((rule) => {
    const policy = rule.policy || {};
    const ratio = policy.limit_bytes
      ? Math.min(100, (policy.usage_bytes / policy.limit_bytes) * 100)
      : 0;
    const blocked = Boolean(policy.blocked);
    const typeLabel = rule.target_type === "user" ? "用户" : "设备";
    const stateLabel = blocked
      ? (state.enforcementSupported ? "已自动封锁" : "已达到上限")
      : policy.bypassed
        ? "本月已解锁"
        : "规则生效中";
    const stateHint = policy.bypassed
      ? "下月恢复执行"
      : blocked
        ? `使用率 ${ratio.toFixed(1)}%`
        : `剩余 ${formatBytes(Math.max(0, policy.limit_bytes - policy.usage_bytes), true)}`;
    return `
      <article class="rule-card ${rule.target_type} ${blocked ? "blocked" : ""}">
        <div class="rule-identity">
          <span class="rule-type">${typeLabel}</span>
          <span>
            <b>${escapeHtml(rule.target_name)}</b>
            <small>${escapeHtml(rule.subtitle)}</small>
          </span>
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
        <button
          class="rule-edit-button"
          type="button"
          data-target-type="${escapeHtml(rule.target_type)}"
          data-target-key="${escapeHtml(rule.target_key)}"
        >编辑规则</button>
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
          rule.policy
        );
      }
    });
  });
}

async function loadRules() {
  try {
    const response = requireLogin(await fetch("/api/policies"));
    if (!response.ok) throw new Error("读取限额规则失败");
    const payload = await response.json();
    state.rules = payload.rules || [];
    state.enforcementSupported = Boolean(payload.enforcement_supported);
    renderRules(state.rules);
  } catch (error) {
    showToast(error.message);
  }
}

function renderUsers(users, total, enforcementSupported) {
  const list = $("#usersList");
  const empty = $("#emptyState");
  const tailnetCount = users.filter((user) => user.network_scope === "tailnet").length;
  const externalCount = users.filter((user) => user.network_scope === "external").length;
  $("#userCount").textContent = `${users.length} 位 · 本网 ${tailnetCount} / 外部 ${externalCount}`;

  if (!users.length) {
    list.innerHTML = "";
    list.hidden = true;
    empty.hidden = false;
    return;
  }

  list.hidden = false;
  empty.hidden = true;
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
    return `
      <article class="exit-user-card">
        <header class="exit-user-header">
          <div class="person">
            <span class="avatar">${escapeHtml(initials(user.name))}</span>
            <span class="person-copy">
              <b>${escapeHtml(user.name)}</b>
              <span>${escapeHtml(user.login_name || user.key)}</span>
            </span>
          </div>
          <div class="exit-user-labels">
            <span class="scope-badge ${scope.className}">${scope.label}</span>
            ${policyBadge(user.policy, enforcementSupported)}
            <span class="device-count"><i class="online-dot ${user.online ? "on" : ""}"></i>${devices.length} 台设备</span>
          </div>
          <div class="exit-user-actions">
            <button
              type="button"
              class="user-alias-button"
              data-user-key="${escapeHtml(user.key)}"
            >修改备注</button>
            <button
              type="button"
              class="user-policy-inline-button ${user.policy?.blocked ? "blocked" : ""}"
              data-user-key="${escapeHtml(user.key)}"
            >${user.policy?.limit_bytes ? `用户限额 · ${policySummary(user.policy, enforcementSupported)}` : "设置用户限额"}</button>
          </div>
        </header>

        <div class="user-usage-summary">
          <div><span>下载</span><strong>${formatBytes(user.download, true)}</strong></div>
          <div><span>上传</span><strong>${formatBytes(user.upload, true)}</strong></div>
          <div><span>用户总计</span><strong>${formatBytes(user.total, true)}</strong></div>
          <div>
            <span>占全部出口流量</span>
            <strong>${share.toFixed(1)}%</strong>
            <span class="user-share-track"><i style="width:${Math.min(100, share)}%"></i></span>
          </div>
        </div>

        <div class="user-devices-heading">
          <div class="user-devices-heading-copy">
            <span>所属设备与用量</span>
            <small>未归属流量 ${formatBytes(unassignedTotal, true)}</small>
          </div>
          <div class="device-column-labels" aria-hidden="true">
            <span>下载</span><span>上传</span><span>总计</span>
          </div>
          <span class="device-action-spacer" aria-hidden="true"></span>
        </div>
        <div class="inline-device-list">
          ${devices.length ? devices.map((device) => `
            <article class="inline-device">
              <div class="inline-device-identity">
                <div class="inline-device-title">
                  <b><i class="online-dot ${device.online ? "on" : ""}"></i>${escapeHtml(device.device_name || "未知设备")}</b>
                  <span>${escapeHtml(device.os_name || "未知系统")}</span>
                </div>
                <div class="inline-device-addresses">
                  ${(device.addresses || []).map((address) => `
                    <small><em>IPv${address.family}</em>${escapeHtml(address.ip)}</small>
                  `).join("")}
                </div>
              </div>
              <div class="inline-device-traffic">
                <span aria-label="下载 ${formatBytes(device.download, true)}"><b>${formatBytes(device.download, true)}</b></span>
                <span aria-label="上传 ${formatBytes(device.upload, true)}"><b>${formatBytes(device.upload, true)}</b></span>
                <span aria-label="总计 ${formatBytes(device.total, true)}"><b>${formatBytes(device.total, true)}</b></span>
              </div>
              <button
                type="button"
                class="inline-device-policy-button ${device.policy?.blocked ? "blocked" : ""}"
                data-user-key="${escapeHtml(user.key)}"
                data-device-id="${escapeHtml(device.device_id)}"
              >${device.policy?.limit_bytes ? policySummary(device.policy, enforcementSupported) : "设置限额"}</button>
            </article>
          `).join("") : '<div class="no-devices">暂无关联设备</div>'}
        </div>
      </article>
    `;
  }).join("");

  list.querySelectorAll(".user-alias-button").forEach((button) => {
    button.addEventListener("click", () => {
      const user = state.payload?.users.find(
        (item) => item.key === button.dataset.userKey
      );
      if (user) openAliasDialog(user);
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
  const padding = { top: 8, right: 2, bottom: 30, left: 43 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maxRaw = Math.max(1, ...daily.map((item) => item.upload + item.download));
  const max = maxRaw * 1.14;
  const unit = chartUnit(max);

  ctx.clearRect(0, 0, width, height);
  ctx.font = '12px Inter, "PingFang SC", sans-serif';
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

function openAliasDialog(user) {
  state.selectedUser = user;
  $("#dialogTitle").textContent = `${user.name} · 修改备注`;
  $("#aliasInput").value = user.name;
  $("#userDialog").showModal();
}

function openPolicy(targetType, targetKey, targetName, policy) {
  state.activePolicyTarget = {
    targetType,
    targetKey,
    targetName,
    policy,
  };
  $("#policyTitle").textContent = targetType === "user"
    ? `${targetName} · 用户总量`
    : `${targetName} · 设备流量`;
  $("#policyUsage").textContent = formatBytes(policy?.usage_bytes || 0, true);

  const status = $("#policyStatus");
  status.className = "";
  if (!policy?.limit_bytes) {
    status.textContent = "尚未设置规则，当前不会自动封锁";
  } else if (policy.blocked) {
    status.textContent = state.enforcementSupported
      ? "已达到月度上限，当前已封锁"
      : "已达到月度上限；Windows 本地测试不执行封锁";
    status.classList.add("blocked");
  } else if (policy.bypassed) {
    status.textContent = "本月已手动解锁，次月重新执行该规则";
    status.classList.add("bypassed");
  } else {
    status.textContent = `规则生效中 · 上限 ${formatBytes(policy.limit_bytes, true)}`;
  }

  const limit = formatLimitInput(policy?.limit_bytes);
  $("#policyLimitValue").value = limit.value;
  $("#policyLimitUnit").value = limit.unit;
  $("#deletePolicy").hidden = !policy?.limit_bytes;
  $("#unlockPolicy").hidden = !policy?.blocked;
  $("#policyEnforcementNote").textContent = state.enforcementSupported
    ? "达到上限后将同时封锁该目标的 IPv4 和 IPv6；下月用量归零后自动解除。"
    : "当前为 Windows 本地测试模式，只显示规则与超限状态；部署到 Linux VPS 后才会实际封锁。";
  $("#policyDialog").showModal();
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
    await refreshAfterPolicyChange("流量限额已保存");
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
    await refreshAfterPolicyChange("流量限额已删除");
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

async function saveAlias() {
  if (!state.selectedUser) return;
  const button = $("#saveAlias");
  button.disabled = true;
  try {
    const response = requireLogin(
      await fetch(`/api/users/${encodeURIComponent(state.selectedUser.key)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias: $("#aliasInput").value.trim() }),
      })
    );
    if (!response.ok) throw new Error("保存失败");
    showToast("备注名已保存");
    $("#userDialog").close();
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
    const response = requireLogin(
      await fetch(`/api/dashboard${month ? `?month=${month}` : ""}`)
    );
    if (!response.ok) throw new Error(`面板接口返回 ${response.status}`);
    const payload = await response.json();
    state.payload = payload;
    state.enforcementSupported = Boolean(
      payload.collector?.enforcement_supported
    );
    monthPicker.value = payload.month;
    updateMonthReset();
    renderSummary(payload.summary);
    renderUsers(
      payload.users,
      payload.summary.total,
      state.enforcementSupported
    );
    setCollectorStatus(payload.collector, payload.last_collect);
    renderSystem(payload);
    if (state.currentPage === "overview") drawChart();
  } catch (error) {
    const status = $("#collectorStatus");
    status.classList.add("error");
    status.innerHTML = '<span class="status-dot"></span>面板异常';
    status.title = error.message;
    showToast(error.message);
  }
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
$("#saveAlias").addEventListener("click", saveAlias);
$("#savePolicy").addEventListener("click", savePolicy);
$("#deletePolicy").addEventListener("click", deletePolicy);
$("#unlockPolicy").addEventListener("click", unlockPolicy);
$("#logoutButton").addEventListener("click", logout);
chart.addEventListener("pointermove", handleChartPointer);
chart.addEventListener("pointerleave", () => { tooltip.hidden = true; });
window.addEventListener("resize", drawChart);
window.addEventListener("hashchange", () => {
  showPage(pageFromHash());
});

showPage(pageFromHash());
loadDashboard();
window.setInterval(loadDashboard, 30_000);
