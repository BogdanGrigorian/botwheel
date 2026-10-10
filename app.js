const clockTime = document.getElementById("clock-time");
const clockDate = document.getElementById("clock-date");
const userInfo = document.getElementById("user-info");

// --- Telegram Web App integration (safe when running outside Telegram) ---
const tg = window.Telegram?.WebApp;

if (tg) {
  tg.ready();
  tg.expand();

  // Match Telegram's native theme
  tg.setHeaderColor(tg.themeParams.bg_color || "#17212b");
  tg.setBackgroundColor(tg.themeParams.bg_color || "#0e1621");

  const user = tg.initDataUnsafe?.user;
  if (user) {
    userInfo.textContent = `Logged in as ${user.first_name || "user"} (@${user.username || "no username"})`;
  } else {
    userInfo.textContent = "Running inside Telegram (user data unavailable).";
  }
} else {
  userInfo.textContent = "Running in a browser — open this app through your Telegram bot to get full integration.";
}

// --- Live clock ---
function updateClock() {
  const now = new Date();

  const time = now.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const date = now.toLocaleDateString([], {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  clockTime.textContent = time;
  clockDate.textContent = date;
}

updateClock();
setInterval(updateClock, 1000);
