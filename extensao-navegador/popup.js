"use strict";

const $ = (id) => document.getElementById(id);

const PADRAO = { origem: "", usuario: "camera", senha: "" };

/* Endereço -> origem (http://127.0.0.1:8766 ou https://x.ts.net). */
function normalizarOrigem(texto) {
  let valor = (texto || "").trim().replace(/\/+$/, "");
  if (!valor) return "";
  if (!/^https?:\/\//i.test(valor)) valor = "http://" + valor;
  try {
    return new URL(valor).origin;
  } catch {
    return null;
  }
}

function cabecalho(usuario, senha) {
  const credenciais = `${usuario}:${senha}`;
  return "Basic " + btoa(unescape(encodeURIComponent(credenciais)));
}

/* Permissão para falar com o endereço (pedida uma vez, com clique do usuário). */
async function garantirPermissao(origem) {
  const alvo = `${origem}/*`;
  if (await chrome.permissions.contains({ origins: [alvo] })) return true;
  try {
    return await chrome.permissions.request({ origins: [alvo] });
  } catch {
    return false;
  }
}

/*
 * O <img> não aceita cabeçalho Authorization, então a senha é injetada pela
 * regra de cabeçalhos (declarativeNetRequest) enquanto o popup está aberto.
 */
async function aplicarRegra(origem, usuario, senha) {
  if (!chrome.declarativeNetRequest?.updateSessionRules) return false;
  const regras = [];
  if (usuario || senha) {
    regras.push({
      id: 1,
      action: {
        type: "modifyHeaders",
        requestHeaders: [
          { header: "Authorization", operation: "set", value: cabecalho(usuario, senha) },
        ],
      },
      condition: {
        urlFilter: `${origem}/*`,
        resourceTypes: ["image", "xmlhttprequest", "media", "sub_frame"],
      },
    });
  }
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [1],
    addRules: regras,
  });
  return true;
}

async function buscarCameras(origem, usuario, senha) {
  const resposta = await fetch(`${origem}/`, {
    headers: { Authorization: cabecalho(usuario, senha) },
    cache: "no-store",
  });
  if (resposta.status === 401) {
    throw new Error("Usuário ou senha incorretos. Confira a senha mostrada no aplicativo.");
  }
  if (!resposta.ok) {
    throw new Error(`O aplicativo respondeu com erro ${resposta.status}.`);
  }
  const html = await resposta.text();
  const ids = [...new Set([...html.matchAll(/\/stream\/(\d+)/g)].map((m) => m[1]))];
  return ids;
}

function mostrarTela(tela) {
  $("tela-cameras").hidden = tela !== "cameras";
  $("tela-configurar").hidden = tela !== "configurar";
}

function mostrarErro(texto) {
  const caixa = $("erro");
  caixa.hidden = !texto;
  caixa.textContent = texto || "";
}

function pintarEstado(texto, ehErro) {
  const caixa = $("estado");
  caixa.hidden = !texto;
  caixa.classList.toggle("erro", !!ehErro);
  caixa.textContent = texto || "";
}

async function verCameras() {
  const { origem, usuario, senha } = await chrome.storage.local.get(PADRAO);
  const alvo = normalizarOrigem(origem);
  if (!alvo || !senha) {
    mostrarTela("configurar");
    return;
  }
  mostrarTela("cameras");
  mostrarErro("");
  pintarEstado("Carregando câmeras...", false);
  $("grade").innerHTML = "";

  try {
    const ids = await buscarCameras(alvo, usuario, senha);
    if (!ids.length) {
      pintarEstado(
        "Nenhuma câmera ativa. Adicione uma câmera no aplicativo do computador.",
        false,
      );
      $("rodape").textContent = "";
      return;
    }
    await aplicarRegra(alvo, usuario, senha);
    const grade = $("grade");
    for (const id of ids) {
      const figura = document.createElement("figure");
      figura.className = "painel";
      const img = document.createElement("img");
      img.src = `${alvo}/stream/${id}?_=${Date.now()}`;
      img.alt = `Câmera ${id}`;
      img.loading = "lazy";
      const legenda = document.createElement("figcaption");
      legenda.textContent = `Câmera ${id}`;
      figura.append(img, legenda);
      grade.append(figura);
    }
    pintarEstado("", false);
    $("rodape").textContent = `${ids.length} câmera(s) · ${alvo.replace(/^https?:\/\//, "")}`;
    $("botao-abrir").href = `${alvo}/`;
  } catch (erro) {
    const morto = erro.name === "TypeError" || /Failed to fetch|NetworkError/i.test(erro.message);
    pintarEstado(
      morto
        ? `Não consegui abrir ${alvo}. Confira se o aplicativo está rodando e se este computador está na VPN Tailscale.`
        : erro.message,
      true,
    );
  }
}

async function iniciar() {
  const { origem, usuario, senha } = await chrome.storage.local.get(PADRAO);
  if (origem && senha) {
    await verCameras();
    return;
  }
  mostrarTela("configurar");
  $("endereco").value = origem || "";
  $("usuario").value = usuario || "camera";
  $("senha").value = senha || "";
}

$("formulario").addEventListener("submit", async (evento) => {
  evento.preventDefault();
  const origem = normalizarOrigem($("endereco").value);
  if (!origem) {
    mostrarErro("Endereço inválido. Use algo como http://127.0.0.1:8766 ou https://meu-pc.ts.net");
    return;
  }
  const usuario = $("usuario").value.trim();
  const senha = $("senha").value;

  if (!(await garantirPermissao(origem))) {
    mostrarErro(
      "Permissão negada. Sem ela a extensão não consegue falar com o aplicativo. " +
      "Permita quando o navegador perguntar.",
    );
    return;
  }

  // Confere as credenciais antes de guardar.
  try {
    await buscarCameras(origem, usuario, senha);
  } catch (erro) {
    mostrarErro(erro.message);
    return;
  }

  await chrome.storage.local.set({ origem, usuario, senha });
  await verCameras();
});

$("botao-configurar").addEventListener("click", async () => {
  const { origem, usuario, senha } = await chrome.storage.local.get(PADRAO);
  mostrarTela("configurar");
  mostrarErro("");
  $("endereco").value = origem || "";
  $("usuario").value = usuario || "camera";
  $("senha").value = senha || "";
  $("botao-cancelar").hidden = false;
});

$("botao-cancelar").addEventListener("click", () => mostrarTela("cameras"));
$("botao-recarregar").addEventListener("click", verCameras);

iniciar();
