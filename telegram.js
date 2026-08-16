// ماژول ربات تلگرام: اعلان‌های خودکار + کنترل از راه دور پنل از داخل تلگرام
// کاملا اختیاری است — اگر توکن تنظیم نشود، این ماژول کاری انجام نمی‌دهد.

let pollOffset = 0;
let pollTimer = null;

function api(token, method, params) {
  const url = `https://api.telegram.org/bot${token}/${method}`;
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  }).then(r => r.json()).catch(() => null);
}

async function sendMessage(getSetting, text) {
  const token = getSetting('telegram_bot_token', '');
  const chatId = getSetting('telegram_chat_id', '');
  const enabled = getSetting('telegram_notify', '1') === '1';
  if (!token || !chatId || !enabled) return { skipped: true };
  return api(token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'HTML' });
}

// ارسال یک فایل (مثلا کانفیگ WireGuard/OpenVPN) به چت ادمین
async function sendDocument(getSetting, filename, content, caption) {
  const token = getSetting('telegram_bot_token', '');
  const chatId = getSetting('telegram_chat_id', '');
  if (!token || !chatId) return { skipped: true };
  const form = new FormData();
  form.append('chat_id', chatId);
  if (caption) form.append('caption', caption);
  form.append('document', new Blob([content], { type: 'text/plain' }), filename);
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/sendDocument`, { method: 'POST', body: form });
    return res.json();
  } catch (e) { return null; }
}

// شروع دریافت دستورات ربات (long polling) — هر ۴ ثانیه یک بار
function startPolling(getSetting, handlers) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const token = getSetting('telegram_bot_token', '');
    const chatId = getSetting('telegram_chat_id', '');
    if (!token) return;
    const res = await api(token, 'getUpdates', { offset: pollOffset + 1, timeout: 0 });
    if (!res || !res.ok || !Array.isArray(res.result)) return;
    for (const update of res.result) {
      pollOffset = Math.max(pollOffset, update.update_id);
      const msg = update.message;
      if (!msg || !msg.text) continue;
      const fromId = String(msg.chat.id);

      // اگر chat id هنوز تنظیم نشده، اولین کسی که /start بفرستد آیدی‌اش نمایش داده می‌شود
      // تا ادمین آن را در پنل وارد کند (بدون تنظیم دستی، ربات به هیچ‌کس دیگری پاسخ نمی‌دهد)
      if (!chatId) {
        if (msg.text.trim() === '/start') {
          api(token, 'sendMessage', {
            chat_id: fromId,
            text: `سلام! این آیدی چت شماست:\n<code>${fromId}</code>\nآن را در تنظیمات پنل، بخش «ربات تلگرام» وارد و ذخیره کنید تا ربات فعال شود.`,
            parse_mode: 'HTML',
          });
        }
        continue;
      }

      if (fromId !== chatId) continue; // فقط چت مجاز پاسخ می‌گیرد
      if (handlers.onMessage) await handlers.onMessage(msg.text.trim(), (text) => api(token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'HTML' }));
    }
  }, 4000);
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

module.exports = { sendMessage, sendDocument, startPolling, stopPolling };
