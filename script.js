"use strict";

/* =================== estado e utilidades =================== */

const VERDICTS = ["Muito fraca", "Muito fraca", "Fraca", "Razoável", "Forte", "Excelente"];

// Dicionário de senhas brasileiras comuns.
// Fonte: SambaTu (https://github.com/HideMeBr/SambaTu), MIT License.
const COMMON_BR = new Set();

fetch("common_br.txt")
  .then(r => r.text())
  .then(text => {
    text.split("\n")
        .map(l => l.trim().toLowerCase())
        .filter(l => l.length >= 4)
        .forEach(word => COMMON_BR.add(word));
  })
  .catch(() => { /* sem dicionário local: zxcvbn e HIBP seguem normais */ });

let currentPassword = "";

function formatDuration(seconds) {
  if (!isFinite(seconds)) return "mais que séculos";
  if (seconds < 1) return "instantâneo";
  const nf = new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 1 });
  if (seconds < 60) return nf.format(seconds) + " segundos";
  if (seconds < 3600) return nf.format(seconds / 60) + " minutos";
  if (seconds < 86400) return nf.format(seconds / 3600) + " horas";
  if (seconds < 2592000) return nf.format(seconds / 86400) + " dias";
  if (seconds < 31536000) return nf.format(seconds / 2592000) + " meses";
  if (seconds < 3153600000) return nf.format(seconds / 31536000) + " anos";
  return nf.format(seconds / 3153600000) + " séculos";
}

/* =================== abas =================== */

function showTab(name) {
  document.getElementById("panel-checker").classList.toggle("visible", name === "checker");
  document.getElementById("panel-generator").classList.toggle("visible", name === "generator");
  document.getElementById("tab-btn-checker").classList.toggle("active", name === "checker");
  document.getElementById("tab-btn-generator").classList.toggle("active", name === "generator");
}

/* =================== aba verificar =================== */

const pwInput = document.getElementById("pw-input");
let debounceTimer = null;

pwInput.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(analyze, 150);
});

function toggleVisibility() {
  const btn = document.getElementById("show-btn");
  const hidden = pwInput.type === "password";
  pwInput.type = hidden ? "text" : "password";
  btn.textContent = hidden ? "ocultar" : "mostrar";
}

function analyze() {
  const pw = pwInput.value;
  currentPassword = pw;
  const segments = document.querySelectorAll("#meter span");
  const verdictEl = document.getElementById("verdict");

  const flags = {
    hibp: document.getElementById("flag-hibp"),
    hibpOk: document.getElementById("flag-hibp-ok"),
    hibpErr: document.getElementById("flag-hibp-err")
  };
    Object.values(flags).forEach(f => f.classList.remove("show", "warn"));

  if (!pw) {
    segments.forEach(s => s.className = "");
    verdictEl.textContent = "—";
    verdictEl.className = "verdict";
    document.getElementById("time-fast").textContent = "—";
    document.getElementById("time-slow").textContent = "—";
    document.getElementById("time-online").textContent = "—";
    return;
  }

    // estado de espera: sem força até o veredito de vazamento
  segments.forEach(s => s.className = "");
  verdictEl.className = "verdict waiting";
  document.getElementById("time-fast").textContent = "—";
  document.getElementById("time-slow").textContent = "—";
  document.getElementById("time-online").textContent = "—";

  // força é calculada agora, mas só exibida se o vazamento liberar
  let score, times;
  if (typeof zxcvbn !== "undefined") {
    const result = zxcvbn(pw);
    score = result.score + 1;
    times = result.crack_times_seconds;
  } else {
    score = heuristicScore(pw);
    times = heuristicTimes(pw, score);
  }

  // senha exatamente na lista de senhas comuns BR
  // força no máximo "fraca", mesmo que o zxcvbn dê nota alta
  if (COMMON_BR.has(pw.toLowerCase()) && score > 2) {
    score = 2;
    times = heuristicTimes(pw, score);
  }

  //offline: aviso amarelo + força normal (não há o que consultar)
  if (!navigator.onLine) {
    flags.hibpErr.textContent = "Você está offline, não é possível verificar se sua senha foi vazada publicamente.";
    flags.hibpErr.classList.add("show", "warn");
    renderStrength(score, times);
    return;
  }

  checkHibp(pw, score, times);
}

function heuristicScore(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  if (COMMON_BR.has(pw.toLowerCase())) s = 1;
  return Math.max(1, Math.min(5, s));
}

function heuristicTimes(pw, score) {
  // estimativa grosseira
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  pool = Math.max(pool, 10);
  const guesses = Math.pow(pool, pw.length) / (COMMON_BR.has(pw.toLowerCase()) ? 1e6 : 1);
  return {
    offline_fast_hashing_1e10_per_second: guesses / 1e10,
    offline_slow_hashing_1e4_per_second: guesses / 1e4,
    online_no_throttling_10_per_second: guesses / 10
  };
}

function renderStrength(score, times) {
  const segments = document.querySelectorAll("#meter span");
  const verdictEl = document.getElementById("verdict");
  segments.forEach((s, i) => { s.className = i < score ? "on-" + score : ""; });
  verdictEl.textContent = VERDICTS[score];
  verdictEl.className = "verdict v-" + (score - 1);
  document.getElementById("time-fast").textContent = formatDuration(times.offline_fast_hashing_1e10_per_second);
  document.getElementById("time-slow").textContent = formatDuration(times.offline_slow_hashing_1e4_per_second);
  document.getElementById("time-online").textContent = formatDuration(times.online_no_throttling_10_per_second);
}

async function checkHibp(pw, score, times) { 
  const flags = {
    bad: document.getElementById("flag-hibp"),
    ok: document.getElementById("flag-hibp-ok"),
    err: document.getElementById("flag-hibp-err")
  };

  try {
    if (!window.crypto || !crypto.subtle) throw new Error("sem WebCrypto");
    const data = new TextEncoder().encode(pw);
    const digest = await crypto.subtle.digest("SHA-1", data);
    const hash = Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();

    const res = await fetch("https://api.pwnedpasswords.com/range/" + hash.slice(0, 5));
    if (!res.ok) throw new Error("falha HTTP " + res.status);
    const text = await res.text();

    // só prossegue se o usuário ainda está digitando a mesma senha
    if (currentPassword !== pw) return;

    let count = 0;
    for (const line of text.split("\n")) {
      const [suffix, occurrences] = line.trim().split(":");
      if (suffix === hash.slice(5)) { count = parseInt(occurrences, 10); break; }
    }

    flags.err.classList.remove("show");

    if (count > 0) {
      // vazou nao mostra forca ou tempo
      flags.bad.textContent = "Encontrada em " + new Intl.NumberFormat("pt-BR").format(count) +
        " vazamentos conhecidos. Se você usa essa senha em algum lugar, troque agora.";
      flags.bad.classList.add("show");
    } else {
      flags.ok.classList.add("show");
      renderStrength(score, times);
    }

   } catch (e) {
    if (currentPassword !== pw) return;
    flags.ok.classList.remove("show");
    if (!navigator.onLine) {
      flags.err.textContent = "Você está offline, não é possível verificar se sua senha foi vazada publicamente.";
      flags.err.classList.add("show", "warn");
    } else {
      flags.err.textContent = "Não foi possível consultar vazamentos agora. " +
        "Sua senha continua protegida, nada foi enviado.";
      flags.err.classList.add("show");
    }
    renderStrength(score, times); // consulta falhou ≠ senha verificada; força volta como fallback
  }
}

/* =================== status de conexão =================== */

function updateStatus() {
  const el = document.getElementById("net-status");
  if (!el) return;
  el.textContent = navigator.onLine
    ? "Online: Verificação de vazamentos ativa, toda a análise de força roda no seu dispositivo"
    : "Offline: Análise de força funciona 100% normalmente, apenas a checagem de vazamentos fica indisponível";
}

window.addEventListener("online", updateStatus);
window.addEventListener("offline", updateStatus);
updateStatus();

/* =================== aba gerar =================== */

const CHARSETS = {
  lower:  "abcdefghijklmnopqrstuvwxyz",
  upper:  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  special:"!@#$%^&*()-_=+[]{};:,.<>?/"
};

// inteiro aleatório uniforme em [0, max) usando Web Crypto
function randomInt(max) {
  const limit = Math.floor(4294967296 / max) * max;
  const buf = new Uint32Array(1);
  let v;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function onLengthChange() {
  document.getElementById("length-value").textContent = document.getElementById("length-slider").value;
  generate();
}

function regenerateIfValid() {
  // impede que todas as categorias fiquem desmarcadas:
  // se o usuário desmarcou a última ativa, religa minúsculas
  if (!anyClassSelected()) {
    document.getElementById("opt-lower").checked = true;
  }
  generate();
}

function anyClassSelected() {
  return ["opt-lower", "opt-upper", "opt-digits", "opt-special"]
    .some(id => document.getElementById(id).checked);
}

function generate() {
  if (!anyClassSelected()) return;

  const length = parseInt(document.getElementById("length-slider").value, 10);
  const ensure = document.getElementById("opt-ensure").checked;

  const active = [];
  if (document.getElementById("opt-lower").checked) active.push(CHARSETS.lower);
  if (document.getElementById("opt-upper").checked) active.push(CHARSETS.upper);
  if (document.getElementById("opt-digits").checked) active.push(CHARSETS.digits);
  if (document.getElementById("opt-special").checked) active.push(CHARSETS.special);
  const pool = active.join("");

  const chars = [];

  if (ensure && length >= active.length) {
    // garante 1 caractere de cada classe selecionada
    for (const set of active) chars.push(set[randomInt(set.length)]);
  }
  while (chars.length < length) {
    chars.push(pool[randomInt(pool.length)]);
  }
  shuffle(chars);

  const pw = chars.slice(0, length).join("");
  document.getElementById("gen-output").textContent = pw;
}

function copyGenerated() {
  const text = document.getElementById("gen-output").textContent;
  if (!text || text.startsWith("Clique")) return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copy-btn");
    const original = btn.textContent;
    btn.textContent = "Copiado!";
    setTimeout(() => { btn.textContent = original; }, 1500);
  }).catch(() => {
    alert("Não foi possível copiar automaticamente. Selecione e copie manualmente.");
  });
}

/* estado inicial */
generate();
