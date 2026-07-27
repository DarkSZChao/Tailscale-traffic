const form = document.querySelector("#loginForm");
const password = document.querySelector("#password");
const button = document.querySelector("#loginButton");
const errorMessage = document.querySelector("#loginError");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.textContent = "";
  button.disabled = true;
  button.textContent = "验证中";

  try {
    const response = await fetch("/api/login", {
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
    button.textContent = "进入";
  }
});

