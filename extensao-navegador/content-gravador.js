"use strict";

const STORAGE_KEY = "gravador_terra_blur_remover";
const DEFAULT_CONFIG = {
  ativo: false,
  modo: "automatico", // automatico | manual
};

function getConfig() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([STORAGE_KEY], (res) => {
        resolve({ ...DEFAULT_CONFIG, ...(res[STORAGE_KEY] || {}) });
      });
    } catch {
      resolve({ ...DEFAULT_CONFIG });
    }
  });
}

function setConfig(config) {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.set({ [STORAGE_KEY]: config }, resolve);
    } catch {
      resolve();
    }
  });
}

function removerBorrao() {
  try {
    // CSS para remover filtros/blur comuns
    const styleId = "gravador-terra-sem-blur";
    if (document.getElementById(styleId)) return;

    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      * {
        filter: none !important;
        -webkit-filter: none !important;
        backdrop-filter: none !important;
        -webkit-backdrop-filter: none !important;
        blur: none !important;
        -webkit-blur: none !important;
      }
      img, video, canvas, .blur, [class*="blur"], [style*="blur"] {
        filter: none !important;
        -webkit-filter: none !important;
      }
      .vjs-blur, .player-blur, .mask-blur, .watermark-blur {
        filter: none !important;
        -webkit-filter: none !important;
        display: none !important;
        visibility: hidden !important;
      }
      [class*="mosaic"], [class*="pixel"], [class*="obfus"] {
        filter: none !important;
        -webkit-filter: none !important;
      }
    `;
    (document.documentElement || document.head || document.body).appendChild(style);
  } catch (e) {
    // ignorar
  }
}

function restaurar() {
  try {
    const style = document.getElementById("gravador-terra-sem-blur");
    if (style) style.remove();
  } catch (e) {
    // ignorar
  }
}

async function aplicar() {
  const config = await getConfig();
  if (!config.ativo) {
    restaurar();
    return;
  }
  if (config.modo === "manual") {
    removerBorrao();
    return;
  }
  // modo automatico
  removerBorrao();
}

let observer = null;
function iniciarObservador() {
  if (observer) return;
  try {
    observer = new MutationObserver(() => {
      aplicar();
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
    });
  } catch (e) {
    // ignorar
  }
}

function pararObservador() {
  if (observer) {
    try {
      observer.disconnect();
    } catch (e) {}
    observer = null;
  }
}

async function init() {
  await aplicar();
  iniciarObservador();
  // Reaplicar em intervalos para garantir (caso página troque elementos)
  setInterval(aplicar, 2000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  init();
}

// Ouvir mudanças de config
try {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[STORAGE_KEY]) {
      aplicar();
    }
  });
} catch (e) {}

// Expor funções para uso via message
try {
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.tipo === "gravador_terra_toggle") {
      getConfig().then((cfg) => {
        const novo = { ...cfg, ativo: !!msg.ativo, modo: msg.modo || cfg.modo };
        setConfig(novo).then(() => {
          aplicar();
          sendResponse({ ok: true, config: novo });
        });
      });
      return true;
    }
    if (msg && msg.tipo === "gravador_terra_get") {
      getConfig().then((cfg) => {
        aplicar();
        sendResponse({ ok: true, config: cfg });
      });
      return true;
    }
    if (msg && msg.tipo === "gravador_terra_aplicar_agora") {
      aplicar();
      sendResponse({ ok: true });
      return false;
    }
  });
} catch (e) {}
