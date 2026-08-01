const form = document.querySelector("#loginForm");
const password = document.querySelector("#password");
const confirmPassword = document.querySelector("#confirmPassword");
const confirmGroup = document.querySelector("#confirmGroup");
const button = document.querySelector("#loginButton");
const errorMessage = document.querySelector("#loginError");
let setupMode = false;

async function loadAuthStatus() {
  try {
    const response = await fetch("/api/auth/status");
    if (!response.ok) throw new Error("无法读取初始化状态");
    const payload = await response.json();
    setupMode = !payload.configured;
    document.querySelector("#loginTitle").textContent = setupMode
      ? "开始使用。"
      : "欢迎回来。";
    document.querySelector("#loginCopy").textContent = setupMode
      ? "首次打开面板，请设置一个仅用于此控制面板的密码。"
      : "输入面板密码，查看出口节点本月的流量使用情况。";
    document.querySelector("#passwordLabel").textContent = setupMode
      ? "设置面板密码"
      : "面板密码";
    password.autocomplete = setupMode ? "new-password" : "current-password";
    confirmGroup.hidden = !setupMode;
    confirmPassword.required = setupMode;
    button.textContent = setupMode ? "设置并进入" : "进入";
    document.querySelector("#loginNote").textContent = setupMode
      ? "密码会以安全哈希保存在本机数据库中，不再使用 .env。"
      : "会话保存在此浏览器中，修改后台密码会自动使旧会话失效。";
  } catch (error) {
    errorMessage.textContent = error.message;
    button.disabled = true;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.textContent = "";
  if (setupMode && password.value !== confirmPassword.value) {
    errorMessage.textContent = "两次输入的密码不一致";
    confirmPassword.select();
    return;
  }
  button.disabled = true;
  button.textContent = setupMode ? "正在设置" : "验证中";

  try {
    const response = await fetch(setupMode ? "/api/setup" : "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password.value }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || "登录失败");
    }
    window.location.replace("/");
  } catch (error) {
    errorMessage.textContent = error.message;
    password.select();
  } finally {
    button.disabled = false;
    button.textContent = setupMode ? "设置并进入" : "进入";
  }
});

loadAuthStatus();
