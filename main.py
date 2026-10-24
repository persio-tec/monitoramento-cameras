"""Aplicativo local para visualizar câmeras e transmiti-las pela VPN Tailscale
ou por um túnel SSH."""

import base64
import getpass
import hashlib
import html
import ipaddress
import json
import os
import pwd
import queue
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as escapar_xml
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog

try:
    import cv2
    from PIL import Image, ImageTk
except ImportError as exc:
    raise SystemExit("Dependências ausentes. Instale com: pip install opencv-python pillow") from exc

try:
    import qrcode
except ImportError:
    qrcode = None


PASTA_CAPTURAS = Path(__file__).resolve().parent / "capturas"
PASTA_CAPTURAS.mkdir(exist_ok=True)
PASTA_DADOS = Path.home() / ".local" / "share" / "monitoramento-cameras"
ARQUIVO_SENHA = PASTA_DADOS / "senha-web.txt"
ARQUIVO_SENHA_SEGURANCA = PASTA_DADOS / "senha-seguranca.txt"
ARQUIVO_TOKEN = PASTA_DADOS / "token-acesso.txt"
PORTA_WEB = 8766
USUARIO_WEB = "camera"
USUARIO_SSH_PADRAO = "cameras"
ITERACOES_HASH_SENHA = 600_000
PORTAS_RTSP = (554, 8554)
# Portas típicas de CMS/DVR (XMEYE, Dahua, Hikvision) usadas pelo app CMS.
PORTAS_CMS = (9530, 5050, 34567, 34599, 37777, 37778, 8000, 6036)
# Portas extras para câmeras Yoosee/Gwell/XMEYE em modo LAN
PORTAS_YOOSEE = (80, 81, 82, 88, 8080, 8000, 34567, 37777, 554, 8554, 10554)
TIMEOUT_BUSCA_REDE = 0.6


def detectar_redes_wifi():
    """Detecta redes Wi-Fi disponíveis com SSID, sinal, segurança."""
    redes = []
    # nmcli
    try:
        resultado = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE", "dev", "wifi", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for linha in resultado.stdout.splitlines():
            if not linha.strip():
                continue
            partes = linha.split(":")
            if len(partes) < 4:
                continue
            ssid = partes[0]
            if not ssid:
                continue
            sinal = partes[1]
            seg = partes[2] or "OPEN"
            in_use = partes[3] == "*"
            redes.append({
                "ssid": ssid,
                "sinal": sinal,
                "seguranca": seg,
                "conectado": in_use,
            })
    except (OSError, subprocess.SubprocessError):
        pass
    # iwlist fallback
    if not redes:
        try:
            resultado = subprocess.run(
                ["iwlist", "scan"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            atual_ssid = None
            atual = {}
            for linha in resultado.stdout.splitlines():
                linha = linha.strip()
                if "Cell" in linha and "Address" in linha:
                    if atual.get("ssid"):
                        redes.append(atual)
                    atual = {}
                    continue
                if "ESSID:" in linha:
                    ssid = linha.split("ESSID:", 1)[1].strip().strip('"')
                    if ssid and ssid != "":
                        atual["ssid"] = ssid
                elif "Quality=" in linha or "Signal level" in linha:
                    m = re.search(r"Quality[^\s]+|level[^\s]+", linha)
                    if m:
                        atual["sinal"] = m.group(0)
                elif "Encryption key:on" in linha:
                    atual.setdefault("seguranca", "WPA/WEP")
                elif "Encryption key:off" in linha and "seguranca" not in atual:
                    atual["seguranca"] = "OPEN"
            if atual.get("ssid"):
                redes.append(atual)
        except (OSError, subprocess.SubprocessError):
            pass
    # remover duplicados mantendo primeiro
    vistos = set()
    unicos = []
    for r in redes:
        key = r["ssid"].lower()
        if key in vistos:
            continue
        vistos.add(key)
        r.setdefault("conectado", False)
        r.setdefault("seguranca", "DESCONHECIDO")
        r.setdefault("sinal", "?")
        unicos.append(r)
    return sorted(unicos, key=lambda x: int(x["sinal"]) if x["sinal"].isdigit() else 0, reverse=True)


def obter_wifi_info():
    """Retorna informações da conexão atual: SSID, IP local e gateway."""
    info = {}
    try:
        resultado = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for linha in resultado.stdout.splitlines():
            if linha.startswith("yes:"):
                info["ssid"] = linha.split(":", 1)[1]
                break
    except (OSError, subprocess.SubprocessError):
        pass
    if "ssid" not in info:
        try:
            resultado = subprocess.run(
                ["iwgetid", "-r"], capture_output=True, text=True, timeout=5
            )
            ssid = resultado.stdout.strip()
            if ssid:
                info["ssid"] = ssid
        except (OSError, subprocess.SubprocessError):
            pass
    ip_local = obter_ip_local()
    if ip_local:
        info["ip"] = ip_local
        partes = ip_local.split(".")
        if len(partes) == 4:
            info["gateway"] = ".".join(partes[:3] + ["1"])
    return info


def obter_ip_local():
    """Retorna o IP local usado na rede padrão (Wi-Fi/LAN), se houver."""
    # Tentar obter via roteamento
    try:
        resultado = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if resultado.stdout:
            m = re.search(r"src\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", resultado.stdout)
            if m:
                ip = m.group(1)
                try:
                    if ipaddress.ip_address(ip) not in ipaddress.ip_network("100.64.0.0/10"):
                        return ip
                except Exception:
                    pass
    except (OSError, subprocess.SubprocessError):
        pass

    # Tentar via nmcli
    try:
        resultado = subprocess.run(
            ["nmcli", "-t", "-f", "IP4.ADDRESS", "device", "show"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for linha in resultado.stdout.splitlines():
            if linha.strip():
                ip = linha.split(":", 1)[-1].split("/")[0].strip()
                try:
                    if ip and ipaddress.ip_address(ip) not in ipaddress.ip_network("100.64.0.0/10"):
                        return ip
                except Exception:
                    pass
    except (OSError, subprocess.SubprocessError):
        pass

    # Fallback: conectar ao DNS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"):
        return None
    return ip


def obter_mac_por_ip(ip):
    """Tenta obter MAC via ip neigh ou arp."""
    try:
        resultado = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if resultado.stdout:
            m = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", resultado.stdout)
            if m:
                return m.group(1).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        resultado = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if resultado.stdout:
            m = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", resultado.stdout)
            if m:
                return m.group(1).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def testar_http_camera(ip, portas=(80, 81, 8080, 8000, 88, 82)):
    """Verifica se há resposta HTTP em portas comuns de câmeras."""
    for porta in portas:
        try:
            conexao = socket.create_connection((ip, porta), timeout=0.6)
            conexao.close()
            return porta
        except OSError:
            continue
    return None


def varredura_detalhada_rede(ip_local, usuario=None, senha=None):
    """Varredura completa: descobre todos os aparelhos com cara de câmera e coleta dados."""
    if not ip_local:
        return []
    prefixo = ".".join(ip_local.split(".")[:3])
    resultados = {}
    trava = threading.Lock()

    portas_scan = tuple(dict.fromkeys([*PORTAS_RTSP, *PORTAS_YOOSEE, 80, 81, 82, 88, 8080, 8000, 8899, 9000]))

    def analisar(ip):
        info = {
            "ip": ip,
            "mac": obter_mac_por_ip(ip),
            "portas_abertas": [],
            "http_porta": None,
            "onvif": False,
            "fabricante": None,
            "modelo": None,
            "serial": None,
            "firmware": None,
            "nome_onvif": None,
            "urls_onvif": [],
            "perfis": [],
            "canais": [],
            "rtsp_encontrados": [],
            "origem": [],
        }
        abertas = []
        for porta in portas_scan:
            try:
                with socket.create_connection((ip, porta), timeout=TIMEOUT_BUSCA_REDE):
                    abertas.append(porta)
            except OSError:
                pass
        if not abertas:
            return
        info["portas_abertas"] = sorted(set(abertas))
        info["http_porta"] = testar_http_camera(ip)
        # Tentar ONVIF
        try:
            onvif_list = descobrir_onvif(ip_local, tempo_espera=1.0)
            for d in onvif_list:
                if d["ip"] == ip:
                    info["onvif"] = True
                    info["urls_onvif"] = d["urls"]
                    info["nome_onvif"] = d["nome"]
                    if not info["origem"]:
                        info["origem"].append("ONVIF")
                    # Tentar obter dados
                    for u in d["urls"]:
                        di, _ = obter_informacoes_device(u, usuario, senha, timeout=2)
                        if di:
                            info["fabricante"] = di.get("fabricante") or info["fabricante"]
                            info["modelo"] = di.get("modelo") or info["modelo"]
                            info["serial"] = di.get("serial") or info["serial"]
                            info["firmware"] = di.get("firmware") or info["firmware"]
                            break
                    # Tentar listar perfis/canais
                    url_midia, _ = _obter_url_midia(d["urls"][0], usuario, senha) if d["urls"] else (None, None)
                    if url_midia:
                        perfis, _ = listar_perfis_midia(url_midia, usuario, senha)
                        info["perfis"] = perfis
                        for p in perfis:
                            url_s, _ = _obter_uri_stream(url_midia, p["token"], p["versao"], usuario, senha)
                            if url_s:
                                url_s = _url_rtsp_com_credenciais(url_s, usuario, senha)
                                info["canais"].append({"nome": p["nome"] or f"Canal", "url": url_s})
        except Exception:
            pass
        # Tentar achar RTSP por caminhos conhecidos
        if not info["rtsp_encontrados"]:
            for p in (554, 8554):
                url = testar_caminhos_rtsp(ip, p)
                if url:
                    info["rtsp_encontrados"].append(url)
                    if not info["origem"]:
                        info["origem"].append("RTSP")
                    break
        if not info["origem"] and info["portas_abertas"]:
            info["origem"].append("PORTAS")
        with trava:
            resultados[ip] = info

    # ARP first
    candidatos = set([ip_local])
    try:
        r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=3)
        for linha in r.stdout.splitlines():
            m = re.match(rf"^({re.escape(prefixo)}\.\d+)\s+", linha)
            if m and m.group(1) != ip_local:
                candidatos.add(m.group(1))
    except Exception:
        pass
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        for linha in r.stdout.splitlines():
            m = re.search(rf"\(({re.escape(prefixo)}\.\d+)\)", linha)
            if m and m.group(1) != ip_local:
                candidatos.add(m.group(1))
    except Exception:
        pass

    with ThreadPoolExecutor(max_workers=150) as executor:
        for host in candidatos:
            if host == ip_local:
                continue
            executor.submit(analisar, host)
        for parte in range(1, 255):
            ip = f"{prefixo}.{parte}"
            if ip != ip_local and ip not in candidatos:
                executor.submit(analisar, ip)

    # Filtrar só os que parecem câmeras
    lista = []
    for ip, info in resultados.items():
        if info["portas_abertas"] or info["onvif"] or info["rtsp_encontrados"] or info["canais"]:
            lista.append(info)
    lista.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
    return lista


def buscar_cameras_rede(ip_local):
    """Procura hosts com porta RTSP/Yoosee aberta na mesma sub-rede /24."""
    prefixo = ".".join(ip_local.split(".")[:3])
    encontrados = []
    trava = threading.Lock()

    # Primeiro coletar IPs já conhecidos via ARP
    candidatos = set()
    try:
        resultado = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for linha in resultado.stdout.splitlines():
            m = re.match(rf"^({re.escape(prefixo)}\.\d+)\s+", linha)
            if m:
                candidatos.add(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        resultado = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for linha in resultado.stdout.splitlines():
            m = re.search(rf"\(({re.escape(prefixo)}\.\d+)\)", linha)
            if m:
                candidatos.add(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass

    portas_busca = tuple(dict.fromkeys([*PORTAS_RTSP, *PORTAS_YOOSEE]))

    def testar(host):
        abertas = []
        for porta in portas_busca:
            try:
                with socket.create_connection(
                    (host, porta), timeout=TIMEOUT_BUSCA_REDE
                ):
                    abertas.append(porta)
            except OSError:
                pass
        # Priorizar portas RTSP
        if abertas:
            rtsp_abertas = [p for p in abertas if p in PORTAS_RTSP]
            if not rtsp_abertas and abertas:
                # Ainda assim registrar se houver outras portas Yoosee
                rtsp_abertas = abertas
            with trava:
                if rtsp_abertas:
                    encontrados.append((host, sorted(set(rtsp_abertas))))

    with ThreadPoolExecutor(max_workers=200) as executor:
        # Testar primeiro os IPs do ARP
        for host in candidatos:
            if host != ip_local:
                executor.submit(testar, host)
        # Depois varrer toda a rede
        for parte in range(1, 255):
            ip = f"{prefixo}.{parte}"
            if ip != ip_local and ip not in candidatos:
                executor.submit(testar, ip)
    return sorted(set(encontrados))


def localizar_camera(identificador, ip_local=None):
    """Localiza uma câmera por IP, ID/serial, nome de host ou índice.

    Retorna (candidatos, erro). Cada candidato é um dicionário com
    ``ip``, ``portas``, ``onvif`` e ``nome``.
    """
    texto = identificador.strip()
    if not texto:
        return [], "Informe o ID, o IP, o nome de host ou o índice da câmera."

    # URL RTSP completa: já é o endereço de conexão.
    if "://" in texto:
        partes = urlsplit(texto)
        if partes.scheme not in ("rtsp", "rtsps"):
            return [], "Use um endereço rtsp:// ou informe IP, ID ou nome de host."
        try:
            porta = partes.port or 554
        except ValueError:
            return [], "A porta informada no endereço é inválida."
        return ([{
            "ip": partes.hostname or texto,
            "portas": [porta],
            "onvif": False,
            "nome": None,
            "url": texto,
        }], None)

    endereco, separador, porta_texto = texto.partition(":")
    if not separador and texto.isdigit():
        return [], (
            "O número informado é um índice de câmera USB. Use o campo "
            "Índice da câmera no topo da janela."
        )
    try:
        ip = ipaddress.ip_address(endereco)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version != 4:
            return [], "Informe um endereço IPv4."
        porta = 554
        if porta_texto:
            if not porta_texto.isdigit():
                return [], "A porta informada é inválida."
            porta = int(porta_texto)
        ip_texto = str(ip)
    else:
        # ID/serial ou nome de host: resolve via rede e via DNS local.
        alvos = []
        if re.fullmatch(r"[0-9a-fA-F]{4,32}", endereco):
            visto = {texto, endereco, endereco.lower(), endereco.upper()}
            if ip_local:
                prefixo = ".".join(ip_local.split(".")[:3])
                for sufixo in ("", "1", "8", "16", ".local"):
                    visto.add(f"{prefixo}.{endereco}{sufixo}")
                    visto.add(f"{endereco}{sufixo}")
            alvos = sorted(visto)
        else:
            visto = {endereco}
            visto.add(endereco.upper())
            visto.add(endereco.lower())
            if not endereco.endswith(".local"):
                visto.add(f"{endereco}.local")
            alvos = sorted(visto)
        for alvo in alvos:
            try:
                ip_texto = socket.gethostbyname(alvo)
                break
            except OSError:
                continue
        else:
            return [], (
                f"Não encontrei a câmera “{texto}”. Confira o ID no rótulo/"
                "etiqueta da câmera ou informe o IP, que aparece no painel do "
                "roteador."
            )
        porta = int(porta_texto) if porta_texto.isdigit() else 554

    candidatos = []
    portas_testar = dict.fromkeys([porta, *PORTAS_RTSP, *PORTAS_YOOSEE])
    for p in portas_testar:
        try:
            with socket.create_connection((ip_texto, p), timeout=TIMEOUT_BUSCA_REDE):
                aberta = True
        except OSError:
            aberta = False
        if aberta:
            candidatos.append({
                "ip": ip_texto,
                "portas": [p],
                "onvif": False,
                "nome": None,
            })
    # Se não achou portas abertas mas é IP direto, ainda assim adicionar candidato
    if not candidatos:
        candidatos.append({
            "ip": ip_texto,
            "portas": [porta],
            "onvif": False,
            "nome": None,
        })
    onvif = descobrir_onvif(ip_local, tempo_espera=1.2) if ip_local else []
    for candidato in candidatos:
        for dispositivo in onvif:
            if dispositivo["ip"] == candidato["ip"]:
                candidato["onvif"] = True
                candidato["nome"] = dispositivo["nome"]
    if not candidatos:
        return [], (
            f"Não foi possível localizar a câmera em {ip_texto}. "
            "Verifique se o IP está correto e se o computador está na mesma rede."
        )

    for candidato in candidatos:
        url_auto = testar_caminhos_rtsp(candidato["ip"], candidato["portas"][0])
        if not url_auto:
            for p in candidato.get("portas", []):
                url_auto = testar_caminhos_rtsp(candidato["ip"], p)
                if url_auto:
                    break
        if url_auto:
            candidato["url"] = url_auto
            candidato["auto"] = True
    return candidatos, None


def _normalizar_id(texto):
    """Deixa um ID/UID comparável: só letras e números, em minúsculas."""
    return re.sub(r"[^0-9a-z]", "", (texto or "").lower())


def _varrer_portas(prefixo, portas, excluir=None):
    """Testa portas em toda a sub-rede /24. Retorna ``{ip: [portas abertas]}``."""
    abertas = {}
    trava = threading.Lock()

    def testar(host, porta):
        try:
            with socket.create_connection((host, porta), timeout=TIMEOUT_BUSCA_REDE):
                aberto = True
        except OSError:
            aberto = False
        if aberto:
            with trava:
                abertas.setdefault(host, []).append(porta)

    with ThreadPoolExecutor(max_workers=128) as executor:
        for parte in range(1, 255):
            ip = f"{prefixo}.{parte}"
            if ip == excluir:
                continue
            for porta in portas:
                executor.submit(testar, ip, porta)
    return {ip: sorted(portas_abertas) for ip, portas_abertas in abertas.items()}


def localizar_camera_cms(identificador, ip_local):
    """Localiza uma câmera pelo ID/UID cadastrado no software CMS.

    Varre a sub-rede pelas portas típicas de CMS/DVR (XMEYE, Dahua,
    Hikvision) e confere se o ID bate com o nome ou o número de série que a
    câmera publica no descobrimento ONVIF. Retorna (candidatos, erro); cada
    candidato tem ``ip``, ``portas``, ``onvif``, ``nome``, ``cms`` e
    ``confere``.
    """
    texto = (identificador or "").strip()
    if not texto:
        return [], "Informe o ID/UID da câmera no CMS (o número da etiqueta)."
    if "://" in texto:
        return [], "Informe o ID/UID do CMS, não um endereço rtsp://."
    try:
        ipaddress.ip_address(texto.split(":")[0])
    except ValueError:
        pass
    else:
        return [], (
            "Esse valor parece um IP. Use o botão “Localizar na rede” para "
            "IP; aqui informe o ID/UID do CMS (o número da etiqueta)."
        )
    if not ip_local:
        return [], "Não foi possível identificar a rede local (Wi-Fi/LAN)."
    alvo = _normalizar_id(texto)
    prefixo = ".".join(ip_local.split(".")[:3])

    candidatos = []
    por_ip = {}
    for dispositivo in descobrir_onvif(ip_local, tempo_espera=2.0):
        comparar = [dispositivo.get("nome") or ""] + list(dispositivo["seriais"])
        casou = bool(alvo) and any(
            alvo in _normalizar_id(item) for item in comparar if item
        )
        candidato = {
            "ip": dispositivo["ip"],
            "portas": [],
            "onvif": True,
            "nome": dispositivo["nome"],
            "cms": False,
            "confere": casou,
        }
        por_ip[dispositivo["ip"]] = candidato
        candidatos.append(candidato)

    abertas = _varrer_portas(
        prefixo, dict.fromkeys([*PORTAS_CMS, *PORTAS_RTSP]), excluir=ip_local
    )
    for ip, portas_abertas in sorted(abertas.items()):
        candidato = por_ip.get(ip)
        if candidato is None:
            candidato = {
                "ip": ip,
                "portas": [],
                "onvif": False,
                "nome": None,
                "cms": False,
                "confere": False,
            }
            por_ip[ip] = candidato
            candidatos.append(candidato)
        candidato["portas"] = portas_abertas
        if any(porta in PORTAS_CMS for porta in portas_abertas):
            candidato["cms"] = True

    if not candidatos:
        return [], (
            "Nenhum aparelho com portas de CMS ou RTSP encontrado na rede "
            "local. O CMS encontra a câmera pela internet (P2P); aqui a "
            "busca é local — confira se o computador está na mesma rede "
            "da câmera ou informe o IP dela."
        )
    candidatos.sort(key=lambda c: (not c["confere"], not c["cms"], c["ip"]))
    return candidatos, None


def rotulo_para_arquivo(rotulo):
    """Deixa um rótulo seguro para uso em nomes de arquivo."""
    return "".join(
        caractere if caractere.isalnum() or caractere in "._-" else "_"
        for caractere in rotulo
    )[:60] or "camera"


def detectar_qr_opencv(imagem):
    """Detecta e decodifica QR code usando OpenCV (QRCodeDetector)."""
    det = cv2.QRCodeDetector()
    try:
        retval, pontos, _ = det.detectAndDecode(imagem)
    except Exception:
        retval = ""
    if retval:
        return retval
    try:
        retval, _, _, pontos2 = det.detectAndDecodeMulti(imagem)
        if retval:
            return retval
    except Exception:
        pass
    return None


def ler_qr_arquivo(caminho):
    """Lê um QR code de um arquivo de imagem."""
    try:
        imagem = cv2.imread(caminho)
        if imagem is None:
            return None
        texto = detectar_qr_opencv(imagem)
        if texto:
            return texto.strip()
        imagem_gray = cv2.cvtColor(imagem, cv2.COLOR_BGR2GRAY)
        texto = detectar_qr_opencv(imagem_gray)
        if texto:
            return texto.strip()
    except Exception:
        pass
    return None


NS_SEGURANCA = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
NS_UTILITY = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
ACAO_PERFIS = "http://www.onvif.org/ver10/media/wsdl/GetProfiles"
ACAO_STREAM = "http://www.onvif.org/ver10/media/wsdl/GetStreamUri"
ACAO_CAPACIDADES = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
ACAO_INFO_DEVICE = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
ACAO_PERFIS_20 = "http://www.onvif.org/ver20/media/wsdl/GetProfiles"
ACAO_STREAM_20 = "http://www.onvif.org/ver20/media/wsdl/GetStreamUri"


def descobrir_onvif(ip_local, tempo_espera=2.5):
    """Descobre câmeras ONVIF na sub-rede via WS-Discovery (UDP 3702)."""
    mensagem = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
        ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        "<e:Header>"
        f"<w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>"
        "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
        "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
        "</w:Action></e:Header><e:Body><d:Probe>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "</d:Probe></e:Body></e:Envelope>"
    ).encode("utf-8")

    prefixo = ".".join(ip_local.split(".")[:3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.settimeout(0.25)
    try:
        try:
            sock.sendto(mensagem, ("239.255.255.250", 3702))
        except OSError:
            pass
        for parte in range(1, 255):
            try:
                sock.sendto(mensagem, (f"{prefixo}.{parte}", 3702))
            except OSError:
                break

        descobertos = {}
        limite = time.monotonic() + tempo_espera
        while time.monotonic() < limite:
            try:
                dados, endereco = sock.recvfrom(65535)
            except (socket.timeout, TimeoutError):
                continue
            texto = dados.decode("utf-8", "replace")
            info = descobertos.setdefault(
                endereco[0],
                {"ip": endereco[0], "urls": set(), "nomes": set(), "seriais": set()},
            )
            for url in re.findall(r"XAddr[^<>]*>([^<]+)<", texto):
                url = url.strip()
                if url and url != "http://www.onvif.org/ver10/schema":
                    info["urls"].add(url)
            for nome in re.findall(r"onvif://www\.onvif\.org/name/([^<\s\"']+)", texto):
                info["nomes"].add(urllib.parse.unquote(nome))
            for serial in re.findall(
                r"onvif://www\.onvif\.org/serial_number/([^<\s\"']+)", texto
            ):
                info["seriais"].add(urllib.parse.unquote(serial))
    finally:
        sock.close()
    return [
        {
            "ip": info["ip"],
            "urls": sorted(info["urls"]),
            "nome": ", ".join(sorted(info["nomes"])) or None,
            "seriais": sorted(info["seriais"]),
        }
        for _, info in sorted(descobertos.items())
    ]


def _cabecalho_seguranca(usuario, senha):
    """Monta o token WS-UsernameToken (PasswordDigest) do ONVIF."""
    nonce = os.urandom(16)
    criado = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(
        hashlib.sha1(nonce + criado.encode("utf-8") + senha.encode("utf-8")).digest()
    ).decode("ascii")
    return (
        f'<s:Security s:mustUnderstand="1" xmlns="{NS_SEGURANCA}"><UsernameToken>'
        f"<Username>{escapar_xml(usuario)}</Username>"
        '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f"{digest}</Password>"
        '<Nonce Encoding="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{base64.b64encode(nonce).decode("ascii")}</Nonce>'
        f'<Created xmlns="{NS_UTILITY}">{criado}</Created>'
        "</UsernameToken></s:Security>"
    )


def _envelope_onvif(corpo, usuario=None, senha=None):
    seguranca = _cabecalho_seguranca(usuario, senha) if usuario else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
        ' xmlns:tr2="http://www.onvif.org/ver20/media/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
        f"<s:Header>{seguranca}</s:Header><s:Body>{corpo}</s:Body></s:Envelope>"
    )


def _post_onvif(url, corpo, acao, usuario=None, senha=None, timeout=4):
    """Envia um SOAP ao serviço ONVIF. Retorna (xml_ou_None, erro_ou_None)."""
    xml = _envelope_onvif(corpo, usuario, senha)
    requisicao = urllib.request.Request(
        url,
        data=xml.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": (
                f'application/soap+xml; charset=utf-8; action="{acao}"'
            ),
        },
    )
    contexto = ssl._create_unverified_context() if url.startswith("https:") else None
    try:
        with urllib.request.urlopen(
            requisicao, timeout=timeout, context=contexto
        ) as resposta:
            return resposta.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as exc:
        texto = exc.read().decode("utf-8", "replace")
        return texto or None, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return None, str(exc)


def _elementos(xml_texto, nome):
    """Lista elementos pelo nome local (ignora namespaces)."""
    try:
        raiz = ET.fromstring(xml_texto)
    except (ET.ParseError, TypeError, ValueError):
        return []
    return [el for el in raiz.iter() if el.tag.rsplit("}", 1)[-1] == nome]


def _possui_falta_autorizacao(xml_texto, erro):
    if erro and "401" in erro:
        return True
    if not xml_texto:
        return False
    return bool(
        re.search(r"NotAuthorized|Unauthorized|Sender not authorized", xml_texto, re.I)
    )


def _possui_falta(xml_texto):
    return bool(xml_texto) and bool(_elementos(xml_texto, "Fault"))


def _obter_url_midia(url_device, usuario, senha):
    """Descobre o endereço do serviço de mídia ONVIF (GetCapabilities)."""
    corpo = "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>"
    xml, erro = _post_onvif(url_device, corpo, ACAO_CAPACIDADES, usuario, senha)
    if xml and not _possui_falta(xml):
        for capacidade in _elementos(xml, "Media"):
            for filho in capacidade:
                if filho.tag.rsplit("}", 1)[-1] == "XAddr" and filho.text:
                    return filho.text.strip(), None
    partes = urlsplit(url_device)
    base = f"{partes.scheme}://{partes.netloc}"
    candidatos = [
        url_device,
        f"{base}/onvif/media_service",
        f"{base}/onvif/media",
    ]
    ultimo_erro = erro or "serviço de mídia não encontrado"
    for url in dict.fromkeys(candidatos):
        xml, erro = _post_onvif(
            url, "<trt:GetProfiles/>", ACAO_PERFIS, usuario, senha
        )
        if xml and not _possui_falta(xml):
            return url, None
        ultimo_erro = erro or ultimo_erro
    return None, ultimo_erro


def _obter_token_perfil(url_midia, usuario, senha):
    xml, erro = _post_onvif(url_midia, "<trt:GetProfiles/>", ACAO_PERFIS, usuario, senha)
    if xml and not _possui_falta(xml):
        for perfil in _elementos(xml, "Profiles"):
            token = perfil.get("token")
            if token:
                return token, "ver10", None
    xml, erro_20 = _post_onvif(
        url_midia, "<tr2:GetProfiles/>", ACAO_PERFIS_20, usuario, senha
    )
    if xml and not _possui_falta(xml):
        for perfil in _elementos(xml, "Profiles"):
            token = perfil.get("token")
            if token:
                return token, "ver20", None
    return None, None, erro or erro_20 or "nenhum perfil de mídia retornado"


def _obter_uri_stream(url_midia, token, versao, usuario, senha):
    if versao == "ver20":
        corpo = (
            "<tr2:GetStreamUri>"
            "<tr2:StreamSetup>"
            "<tt:Stream>RTP-Unicast</tt:Stream>"
            "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
            "</tr2:StreamSetup>"
            f"<tr2:ProfileToken>{escapar_xml(token)}</tr2:ProfileToken>"
            "</tr2:GetStreamUri>"
        )
        acao = ACAO_STREAM_20
    else:
        corpo = (
            "<trt:GetStreamUri>"
            "<trt:StreamSetup>"
            "<tt:Stream>RTP-Unicast</tt:Stream>"
            "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
            "</trt:StreamSetup>"
            f"<trt:ProfileToken>{escapar_xml(token)}</trt:ProfileToken>"
            "</trt:GetStreamUri>"
        )
        acao = ACAO_STREAM
    xml, erro = _post_onvif(url_midia, corpo, acao, usuario, senha)
    if xml and not _possui_falta(xml):
        for uri in _elementos(xml, "Uri"):
            if uri.text and uri.text.strip().startswith("rtsp"):
                return uri.text.strip(), None
    return None, erro or "a câmera não informou o URL RTSP"


def obter_uri_rtsp(url_device, usuario=None, senha=None):
    """Obtém o URL RTSP de uma câmera ONVIF. Retorna (url_ou_None, erro)."""
    url_midia, erro = _obter_url_midia(url_device, usuario, senha)
    if url_midia is None:
        return None, f"sem acesso ao serviço de mídia ({erro})"
    token, versao, erro = _obter_token_perfil(url_midia, usuario, senha)
    if token is None:
        return None, f"sem acesso aos perfis ({erro})"
    return _obter_uri_stream(url_midia, token, versao, usuario, senha)


def obter_informacoes_device(url_device, usuario=None, senha=None, timeout=3):
    """Lê fabricante, modelo e número de série do aparelho (GetDeviceInformation).

    Retorna (info_ou_None, erro). ``info`` tem ``fabricante``, ``modelo``,
    ``serial`` e ``firmware`` para cada campo que o aparelho informar.
    """
    xml, erro = _post_onvif(
        url_device,
        "<tds:GetDeviceInformation/>",
        ACAO_INFO_DEVICE,
        usuario,
        senha,
        timeout,
    )
    if _possui_falta_autorizacao(xml, erro):
        return None, "usuário ou senha incorretos"
    if not xml or _possui_falta(xml):
        return None, erro or "sem acesso às informações do dispositivo"
    info = {}
    for campo, chave in (
        ("Manufacturer", "fabricante"),
        ("Model", "modelo"),
        ("SerialNumber", "serial"),
        ("FirmwareVersion", "firmware"),
    ):
        elementos = _elementos(xml, campo)
        if elementos and elementos[0].text and elementos[0].text.strip():
            info[chave] = elementos[0].text.strip()
    return info or None, None


def listar_perfis_midia(url_midia, usuario, senha):
    """Lista os perfis (canais) do serviço de mídia ONVIF de um NVR.

    Retorna (perfis, erro). Cada perfil tem ``token``, ``nome`` e ``versao``.
    """
    ultimo_erro = None
    for corpo, acao, versao in (
        ("<trt:GetProfiles/>", ACAO_PERFIS, "ver10"),
        ("<tr2:GetProfiles/>", ACAO_PERFIS_20, "ver20"),
    ):
        xml, erro = _post_onvif(url_midia, corpo, acao, usuario, senha)
        if _possui_falta_autorizacao(xml, erro):
            return [], "usuário ou senha incorretos no NVR"
        if xml and not _possui_falta(xml):
            perfis = []
            for perfil in _elementos(xml, "Profiles"):
                token = perfil.get("token")
                if not token:
                    continue
                nome = None
                for filho in perfil:
                    if filho.tag.rsplit("}", 1)[-1] == "Name" and filho.text:
                        nome = filho.text.strip()
                perfis.append({"token": token, "nome": nome, "versao": versao})
            if perfis:
                return perfis, None
            ultimo_erro = erro or "o NVR não informou canais"
        elif erro:
            ultimo_erro = erro
    return [], ultimo_erro or "nenhum canal retornado pelo NVR"


def _url_rtsp_com_credenciais(url, usuario, senha):
    """Grava usuário/senha no URL RTSP, quando o NVR exige autenticação."""
    if not usuario or not url:
        return url
    try:
        partes = urlsplit(url)
        if partes.scheme not in ("rtsp", "rtsps") or partes.username:
            return url
        credenciais = urllib.parse.quote(usuario, safe="")
        if senha:
            credenciais += ":" + urllib.parse.quote(senha, safe="")
        return urllib.parse.urlunsplit(
            (
                partes.scheme,
                f"{credenciais}@{partes.netloc}",
                partes.path,
                partes.query,
                partes.fragment,
            )
        )
    except (ValueError, AttributeError):
        return url


def listar_canais_nvr(endereco, usuario=None, senha=None):
    """Conecta a um NVR/gravador ONVIF pelo IP e lista os canais (RTSP).

    Retorna (canais, erro). Cada canal é um dicionário com ``nome`` e ``url``.
    """
    texto = (endereco or "").strip()
    if not texto:
        return [], "Informe o IP ou o nome do NVR."
    if "://" in texto:
        base = texto.rstrip("/")
    else:
        base = f"http://{texto.split('/')[0].strip()}"
    partes = urlsplit(base)
    if not partes.netloc or not partes.hostname:
        return [], "Informe o IP ou o nome do NVR (ex.: 192.168.0.10)."
    raiz = f"{partes.scheme}://{partes.netloc}"
    caminhos = ["/onvif/device_service", "/onvif/devices", "/onvif/device", "/onvif"]
    if partes.path and partes.path != "/":
        caminhos.insert(0, partes.path)
    ultimo_erro = None
    for caminho in dict.fromkeys(caminhos):
        url_device = f"{raiz}{caminho}"
        url_midia, erro = _obter_url_midia(url_device, usuario, senha)
        if erro and "401" in erro:
            return [], "usuário ou senha incorretos no NVR"
        if url_midia is None:
            ultimo_erro = erro or ultimo_erro
            continue
        perfis, erro = listar_perfis_midia(url_midia, usuario, senha)
        if not perfis:
            ultimo_erro = erro or ultimo_erro
            continue
        canais = []
        falhas = []
        for indice, perfil in enumerate(perfis, start=1):
            url, erro_stream = _obter_uri_stream(
                url_midia, perfil["token"], perfil["versao"], usuario, senha
            )
            if not url:
                falhas.append(perfil["nome"] or f"canal {indice}: {erro_stream}")
                continue
            canais.append(
                {
                    "nome": perfil["nome"] or f"Canal {indice}",
                    "url": _url_rtsp_com_credenciais(url, usuario, senha),
                }
            )
        if canais:
            return canais, None
        ultimo_erro = "; ".join(falhas[:4]) or ultimo_erro or (
            "o NVR não informou nenhum URL RTSP"
        )
    return [], ultimo_erro or (
        "NVR não respondeu ao ONVIF. Confira o IP e se ele está ligado "
        "na mesma rede."
    )


def carregar_ou_criar_senha():
    PASTA_DADOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PASTA_DADOS, 0o700)
    try:
        senha = ARQUIVO_SENHA.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        senha = secrets.token_urlsafe(18)
        try:
            descritor = os.open(
                ARQUIVO_SENHA, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError:
            senha = ARQUIVO_SENHA.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
                arquivo.write(senha + "\n")
    if len(senha) < 20:
        raise ValueError(f"A senha web em {ARQUIVO_SENHA} é inválida.")
    os.chmod(ARQUIVO_SENHA, 0o600)
    return senha


SCRIPT_USUARIO_SSH = """#!/bin/bash
# Executado com privilégios de root (via pkexec) para criar ou remover o
# usuário SSH de acesso às câmeras. A senha chega pelo arquivo de dados
# apontado em $3 e é apagada assim que é usada.
set -euo pipefail

acao="${1:-}"
usuario="${2:-}"
arquivo_dados="${3:-}"

# Sem hífen: o useradd do Debian recusa esses nomes ("use --badname").
if [[ ! "$usuario" =~ ^[a-z_][a-z0-9_]{0,31}$ ]]; then
    echo "NOME_DE_USUARIO_INVALIDO" >&2
    exit 2
fi

case "$acao" in
criar)
    if [[ ! -r "$arquivo_dados" ]]; then
        echo "ARQUIVO_ILEGIVEL" >&2
        exit 3
    fi
    senha="$(sed -n '1p' "$arquivo_dados")"
    chave="$(sed -n '2p' "$arquivo_dados")"
    rm -f "$arquivo_dados"

    if [[ -z "$senha" ]]; then
        echo "SENHA_VAZIA" >&2
        exit 4
    fi

    if id "$usuario" >/dev/null 2>&1; then
        usermod -s /bin/bash "$usuario"
        casa="$(getent passwd "$usuario" | cut -d: -f6)"
        if [[ ! -d "$casa" ]]; then
            mkdir -p "$casa"
            chown "$usuario" "$casa"
        fi
    else
        useradd -m -s /bin/bash "$usuario"
        casa="$(getent passwd "$usuario" | cut -d: -f6)"
    fi

    printf '%s:%s\\n' "$usuario" "$senha" | chpasswd
    senha=""

    mkdir -p "$casa/.ssh"
    chmod 700 "$casa/.ssh"
    touch "$casa/.ssh/authorized_keys"
    chmod 600 "$casa/.ssh/authorized_keys"
    if [[ -n "$chave" ]] && ! grep -qF "$chave" "$casa/.ssh/authorized_keys"; then
        printf '%s\\n' "$chave" >> "$casa/.ssh/authorized_keys"
    fi
    chown -R "$usuario:$usuario" "$casa/.ssh"
    ;;
remover)
    if id "$usuario" >/dev/null 2>&1; then
        userdel -r "$usuario" 2>/dev/null || userdel "$usuario"
    fi
    ;;
*)
    echo "ACAO_DESCONHECIDA" >&2
    exit 5
    ;;
esac

echo "OK"
"""


def caminho_chave_cameras():
    """Caminho da chave SSH dedicada ao acesso às câmeras."""
    return Path.home() / ".ssh" / "id_ed25519_cameras"


def garantir_chave_cameras():
    """Garante que exista um par de chaves dedicado às câmeras.

    Sem senha (para o túnel não pedir nada) e com o arquivo privado em 600.
    """
    chave = caminho_chave_cameras()
    publica = chave.with_name(chave.name + ".pub")
    if chave.exists() and publica.exists():
        os.chmod(chave, 0o600)
        return chave
    pasta = chave.parent
    pasta.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(pasta, 0o700)
    subprocess.run(
        [
            "ssh-keygen", "-t", "ed25519", "-f", str(chave), "-N", "",
            "-C", "acesso-cameras",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    os.chmod(chave, 0o600)
    return chave


def linha_authorized_keys(chave=None):
    """Linha do authorized_keys com a chave dedicada e as restrições.

    `restrict` desliga PTY, agente e X11; `port-forwarding` religa o
    encaminhamento de portas (que é o que o túnel precisa) e `permitopen`
    limita o destino ao 127.0.0.1 do próprio servidor.
    """
    chave = Path(chave) if chave else caminho_chave_cameras()
    publica = chave.with_name(chave.name + ".pub")
    if not publica.exists():
        raise FileNotFoundError(
            f"A chave pública {publica} não existe."
        )
    conteudo = publica.read_text(encoding="utf-8").strip()
    return f'restrict,port-forwarding,permitopen="127.0.0.1:*" {conteudo}'


def usuario_ssh_existe(usuario):
    """True se já existe uma conta de sistema com esse nome."""
    try:
        pwd.getpwnam(usuario)
    except KeyError:
        return False
    return True


def senha_ssh_aleatoria(tamanho=16):
    """Senha aleatória para o usuário SSH (sem ':' e sem quebra de linha)."""
    alfabeto = (
        "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        "-_."
    )
    return "".join(secrets.choice(alfabeto) for _ in range(tamanho))


def criar_usuario_ssh_sistema(usuario, senha, chave=None):
    """Cria (ou ajusta) o usuário SSH de acesso às câmeras.

    Usa `pkexec`, então o sistema abre a janela de autenticação do
    polkit e é o próprio dono da máquina quem digita a senha de
    administrador — o aplicativo nunca vê essa senha. A senha do usuário
    SSH, essa sim, é a que foi digitada no aplicativo.
    """
    usuario = (usuario or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,31}", usuario):
        raise ValueError(
            "Nome de usuário inválido: use até 32 caracteres em minúsculas, "
            "começando por letra ou _ e sem espaços nem hífen."
        )
    if len(senha) < 8:
        raise ValueError("A senha do usuário SSH precisa ter ao menos 8 caracteres.")
    if ":" in senha or "\n" in senha or "\r" in senha:
        raise ValueError("A senha do usuário SSH não pode conter ':' nem quebra de linha.")

    chave = Path(chave) if chave else caminho_chave_cameras()
    PASTA_DADOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PASTA_DADOS, 0o700)
    script = PASTA_DADOS / "criar-usuario-ssh.sh"
    script.write_text(SCRIPT_USUARIO_SSH, encoding="utf-8")
    os.chmod(script, 0o700)
    arquivo = PASTA_DADOS / ".senha-ssh-tmp"
    descritor = os.open(arquivo, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descritor, "w", encoding="utf-8") as dados:
        dados.write(senha + "\n" + linha_authorized_keys(chave) + "\n")
    try:
        resultado = _executar_como_admin(
            ["criar", usuario, str(arquivo)], arquivo=arquivo
        )
    finally:
        try:
            arquivo.unlink()
        except FileNotFoundError:
            pass
    if resultado.returncode != 0:
        raise RuntimeError(_erro_do_pkexec(resultado))
    return usuario


def remover_usuario_ssh_sistema(usuario):
    """Apaga a conta de sistema de um aparelho (pede autorização ao sistema)."""
    usuario = (usuario or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,31}", usuario):
        raise ValueError("Nome de usuário inválido.")
    resultado = _executar_como_admin(["remover", usuario])
    if resultado.returncode != 0:
        raise RuntimeError(_erro_do_pkexec(resultado))
    return usuario


def _executar_como_admin(argumentos, arquivo=None):
    """Roda o script de manutenção como root via pkexec (janela do sistema)."""
    PASTA_DADOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PASTA_DADOS, 0o700)
    script = PASTA_DADOS / "criar-usuario-ssh.sh"
    script.write_text(SCRIPT_USUARIO_SSH, encoding="utf-8")
    os.chmod(script, 0o700)
    comando = ["pkexec", "/bin/bash", str(script)] + list(argumentos)
    return subprocess.run(
        comando,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _erro_do_pkexec(resultado):
    """Transforma a saída do pkexec em uma mensagem útil para o usuário."""
    detalhe = (resultado.stderr or resultado.stdout or "").strip()
    if resultado.returncode in (126, 127):
        return (
            "Não foi possível pedir permissão de administrador (pkexec). "
            "Abra o app pelo seu desktop para que a janela do sistema apareça."
        )
    if "NOME_DE_USUARIO_INVALIDO" in detalhe:
        return "Nome de usuário inválido."
    if "ARQUIVO_ILEGIVEL" in detalhe:
        return "Arquivo temporário da senha não pôde ser lido."
    if "SENHA_VAZIA" in detalhe:
        return "A senha do usuário SSH ficou vazia."
    if "acao cancel" in detalhe.lower() or "not authorized" in detalhe.lower():
        return "A criação do usuário foi cancelada (sem autorização do sistema)."
    return detalhe or "Falha ao criar o usuário SSH."


ARQUIVO_APARELHOS = PASTA_DADOS / "aparelhos.json"


def carregar_aparelhos():
    """Lista de aparelhos cadastrados (um por conta SSH)."""
    try:
        dados = json.loads(ARQUIVO_APARELHOS.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    return dados if isinstance(dados, list) else []


def salvar_aparelhos(lista):
    PASTA_DADOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    ARQUIVO_APARELHOS.write_text(
        json.dumps(lista, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.chmod(ARQUIVO_APARELHOS, 0o600)


def nome_usuario_aparelho(nome, ja_existentes=()):
    """Deriva um nome de usuário válido e único a partir do nome do aparelho."""
    base = re.sub(r"[^a-z0-9]+", "_", (nome or "").lower()).strip("_")[:18]
    if not base:
        base = "aparelho"
    usuario = f"cam_{base}"
    numero = 2
    while usuario_ssh_existe(usuario) or usuario in ja_existentes:
        usuario = f"cam_{base[:16]}_{numero}"
        numero += 1
    return usuario


def chave_aparelho(usuario):
    """Caminho da chave privada que pertence a um aparelho."""
    return Path.home() / ".ssh" / f"id_ed25519_{usuario}"


def gerar_chave_para(destino, comentario):
    """Gera um par de chaves ed25519 sem senha (túnel não pergunta nada)."""
    destino = Path(destino)
    publica = destino.with_name(destino.name + ".pub")
    if destino.exists() and publica.exists():
        os.chmod(destino, 0o600)
        return destino
    pasta = destino.parent
    pasta.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(pasta, 0o700)
    subprocess.run(
        [
            "ssh-keygen", "-t", "ed25519", "-f", str(destino), "-N", "",
            "-C", comentario,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    os.chmod(destino, 0o600)
    return destino


def carregar_ou_criar_token():
    """Token aleatório que abre a página das câmeras sem pedir login.

    O link http://127.0.0.1:8766/?acesso=TOKEN já entra autenticado: o
    navegador recebe um cookie e não mostra a janela de login. É o mesmo
    nível de acesso que a senha, então o link é tão secreto quanto ela —
    por isso fica num arquivo só do dono (permissão 600).
    """
    PASTA_DADOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PASTA_DADOS, 0o700)
    try:
        token = ARQUIVO_TOKEN.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        token = secrets.token_urlsafe(24)
        try:
            descritor = os.open(
                ARQUIVO_TOKEN, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError:
            token = ARQUIVO_TOKEN.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
                arquivo.write(token + "\n")
    if len(token) < 20:
        raise ValueError(f"O token em {ARQUIVO_TOKEN} é inválido.")
    os.chmod(ARQUIVO_TOKEN, 0o600)
    return token


def salvar_senha_seguranca(senha):
    sal = secrets.token_bytes(16)
    hash_senha = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), sal, ITERACOES_HASH_SENHA
    )
    conteudo = f"pbkdf2_sha256${ITERACOES_HASH_SENHA}${sal.hex()}${hash_senha.hex()}\n"
    descritor = os.open(
        ARQUIVO_SENHA_SEGURANCA,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
        arquivo.write(conteudo)
    os.chmod(ARQUIVO_SENHA_SEGURANCA, 0o600)


def verificar_senha_seguranca(senha):
    try:
        algoritmo, iteracoes, sal_hex, hash_hex = (
            ARQUIVO_SENHA_SEGURANCA.read_text(encoding="utf-8").strip().split("$")
        )
        if algoritmo != "pbkdf2_sha256" or int(iteracoes) < 100_000:
            raise ValueError
        sal = bytes.fromhex(sal_hex)
        hash_salvo = bytes.fromhex(hash_hex)
    except (OSError, ValueError) as exc:
        raise ValueError("A senha de segurança salva está inválida.") from exc
    hash_informado = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), sal, int(iteracoes)
    )
    return secrets.compare_digest(hash_informado, hash_salvo)


FERRAMENTAS_COPIAR = (
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
    ["wl-copy"],
    ["pbcopy"],
)

FERRAMENTAS_COLAR = (
    ["xclip", "-selection", "clipboard", "-output"],
    ["xsel", "--clipboard", "--output"],
    ["wl-paste", "--no-newline"],
    ["pbpaste"],
)


def copiar_texto(widget, texto):
    """Copia texto para a área de transferência.

    Usa a ferramenta do sistema (xclip/xsel/wl-copy/pbcopy) quando existir,
    para o conteúdo continuar na área de transferência depois de fechar o
    app; se não houver nenhuma, fica só com a do Tkinter.
    """
    try:
        widget.clipboard_clear()
        widget.clipboard_append(texto)
    except tk.TclError:
        pass
    for comando in FERRAMENTAS_COPIAR:
        try:
            processo = subprocess.Popen(
                comando,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except (FileNotFoundError, OSError):
            continue
        try:
            processo.communicate(texto, timeout=3)
        except subprocess.TimeoutExpired:
            processo.kill()
        return True
    return False


def obter_texto_colado(widget):
    """Lê o texto da área de transferência (Tkinter e, se preciso, sistema)."""
    try:
        texto = widget.clipboard_get()
        if texto:
            return texto
    except tk.TclError:
        pass
    for comando in FERRAMENTAS_COLAR:
        try:
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        if resultado.returncode == 0 and resultado.stdout:
            return resultado.stdout
    return ""


def analisar_comando_ssh(texto):
    """Lê um comando 'ssh ...' colado e devolve (destino, porta_local) ou None.

    Serve para colar um comando pronto — vindo de um chat, e-mail ou de outro
    computador — e o app preencher os campos sozinho.
    """
    partes = (texto or "").strip().split()
    if len(partes) < 2 or not partes[0].endswith("ssh"):
        return None
    destino = None
    porta_local = None
    porta_ssh = None
    chave = None
    indice = 1
    while indice < len(partes):
        parte = partes[indice]
        if parte == "-L" and indice + 1 < len(partes):
            campos = partes[indice + 1].split(":")
            if campos and campos[0].isdigit():
                porta_local = int(campos[0])
            indice += 2
            continue
        if parte == "-p" and indice + 1 < len(partes):
            if partes[indice + 1].isdigit():
                porta_ssh = int(partes[indice + 1])
            indice += 2
            continue
        if parte == "-i" and indice + 1 < len(partes):
            chave = partes[indice + 1]
            indice += 2
            continue
        if parte in {"-o", "-F", "-J", "-E", "-l"} and indice + 1 < len(partes):
            indice += 2
            continue
        if parte.startswith("-"):
            indice += 1
            continue
        if destino is None:
            destino = parte
        indice += 1
    if not destino:
        return None
    if porta_ssh and porta_ssh != 22 and ":" not in destino:
        destino = f"{destino}:{porta_ssh}"
    return destino, porta_local, chave


def montar_comando_ssh(destino, porta_local=PORTA_WEB, porta_servidor=PORTA_WEB, chave=None):
    """Monta o comando SSH que encaminha a porta do servidor de câmeras.

    `destino` aceita "host", "usuario@host" e "usuario@host:porta" (a porta
    aqui é a do próprio SSH, não a do túnel). `chave` é o caminho da chave
    privada no computador que vai abrir o túnel; em branco, o SSH usa a chave
    padrão. O comando abre um túnel local (port-forwarding) para a porta do
    servidor web, que só escuta em 127.0.0.1 — nada é exposto na internet.
    """
    destino = (destino or "").strip()
    if destino.startswith("ssh "):
        destino = destino[4:].strip()
    if not destino:
        raise ValueError("Informe o servidor SSH (ex.: usuario@192.168.0.10).")
    if any(caractere.isspace() for caractere in destino):
        raise ValueError("O servidor SSH não pode conter espaços.")

    usuario, _, host = destino.rpartition("@")
    if "@" not in destino:
        usuario, host = "", destino
    if not host:
        raise ValueError("Use o formato usuario@host ou apenas host.")

    if host.startswith("["):
        fim = host.find("]")
        if fim < 0:
            raise ValueError("Endereço IPv6 inválido.")
        endereco, resto = host[: fim + 1], host[fim + 1 :]
    elif host.count(":") == 1:
        # "host:porta" (um único ":"; IPv6 sem colchetes tem vários).
        endereco, _, resto = host.partition(":")
        resto = ":" + resto
    else:
        endereco, resto = host, ""

    porta_ssh = 22
    if resto:
        if not resto.startswith(":"):
            raise ValueError("Use o formato host:porta para indicar a porta do SSH.")
        texto_porta = resto[1:]
        if not texto_porta.isdigit() or not 1 <= int(texto_porta) <= 65535:
            raise ValueError("Porta do SSH inválida.")
        porta_ssh = int(texto_porta)

    if not isinstance(porta_local, int) or not 1 <= porta_local <= 65535:
        raise ValueError("Porta local inválida.")

    comando = ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L",
               f"{porta_local}:127.0.0.1:{porta_servidor}"]
    if chave:
        comando.extend(["-i", str(chave)])
    if porta_ssh != 22:
        comando.extend(["-p", str(porta_ssh)])
    comando.append(f"{usuario}@{endereco}" if usuario else endereco)
    return " ".join(comando)


def extrair_host_ssh(destino):
    """Separa o host de "usuario@host", "host" ou "host:porta"."""
    texto = (destino or "").strip()
    if texto.startswith("ssh "):
        texto = texto[4:].strip()
    _, _, host = texto.rpartition("@")
    if host.startswith("["):
        fim = host.find("]")
        return host[: fim + 1] if fim > 0 else host
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def sugestao_ssh_host():
    """Nome desta máquina, para montar o destino do túnel SSH."""
    try:
        return socket.gethostname() or "localhost"
    except OSError:
        return "localhost"


def sugestao_ssh_destino():
    """Sugere o destino do túnel SSH para esta máquina: usuario@host."""
    try:
        usuario = getpass.getuser()
    except (KeyError, OSError):
        usuario = ""
    if usuario_ssh_existe(USUARIO_SSH_PADRAO):
        usuario = USUARIO_SSH_PADRAO
    host = sugestao_ssh_host()
    return f"{usuario}@{host}" if usuario else host


class ServidorCameras(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cameras, senha, token=None):
        self.cameras = cameras
        self.senha = senha
        self.token = token
        self.parar = threading.Event()
        super().__init__(("127.0.0.1", PORTA_WEB), ManipuladorCameras)


class ManipuladorCameras(BaseHTTPRequestHandler):
    server: ServidorCameras

    def _token_valido(self, valor):
        """Confere se o valor é o token de acesso da sessão."""
        token = getattr(self.server, "token", None)
        if not token or not valor:
            return False
        return secrets.compare_digest(valor, token)

    def _token_da_requisicao(self):
        """Token vindo do cookie (sessão) ou da query string (link de acesso)."""
        cookie = self.headers.get("Cookie", "")
        for parte in cookie.split(";"):
            nome, _, valor = parte.strip().partition("=")
            if nome == "cam_acesso" and self._token_valido(valor):
                return valor
        consulta = urllib.parse.parse_qs(urlsplit(self.path).query)
        valores = consulta.get("acesso", [])
        for valor in valores:
            if self._token_valido(valor):
                return valor
        return ""

    def _autorizado(self):
        if self._token_da_requisicao():
            return True
        cabecalho = self.headers.get("Authorization", "").split(" ", 1)
        if len(cabecalho) != 2 or cabecalho[0].lower() != "basic":
            return False
        try:
            credenciais = base64.b64decode(cabecalho[1], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        usuario, separador, senha = credenciais.partition(":")
        return (
            bool(separador)
            and secrets.compare_digest(usuario, USUARIO_WEB)
            and secrets.compare_digest(
                senha.encode("utf-8"), self.server.senha.encode("utf-8")
            )
        )

    def _exigir_senha(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Cameras locais"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _responder(self, status, conteudo, tipo="text/html; charset=utf-8"):
        corpo = conteudo.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        # Link de acesso (/?acesso=TOKEN): o navegador recebe um cookie e
        # entra direto, sem a janela de login.
        consulta = urllib.parse.parse_qs(urlsplit(self.path).query)
        token_url = (consulta.get("acesso") or [""])[0]
        if self._token_valido(token_url):
            self.send_response(302)
            self.send_header(
                "Set-Cookie",
                f"cam_acesso={token_url}; Path=/; HttpOnly; SameSite=Strict",
            )
            self.send_header("Location", "/")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if not self._autorizado():
            self._exigir_senha()
            return

        caminho = urlsplit(self.path).path
        if caminho == "/":
            paineis = []
            for indice, camera in sorted(self.server.cameras.items()):
                if camera.obter_frame() is None:
                    continue
                rotulo_seguro = html.escape(str(camera.rotulo), quote=True)
                paineis.append(
                    f"<section><h2>Câmera {rotulo_seguro}</h2>"
                    f'<img src="/stream/{indice}" alt="Câmera {rotulo_seguro}"></section>'
                )
            conteudo = (
                "<!doctype html><html lang=\"pt-BR\"><meta name=\"viewport\" "
                "content=\"width=device-width,initial-scale=1\"><meta charset=\"utf-8\">"
                "<title>Câmeras locais</title><style>"
                "body{font:16px system-ui;margin:1rem;background:#111827;color:#f9fafb}"
                "section{margin:1rem 0}img{display:block;width:100%;height:auto;"
                "max-height:80vh;object-fit:contain;background:#000}"
                "</style><h1>Câmeras locais</h1>"
                + ("".join(paineis) or
                   "<p>Nenhuma câmera ativa. Adicione uma câmera no aplicativo do computador.</p>")
                + "</html>"
            )
            self._responder(200, conteudo)
            return

        prefixo = "/stream/"
        if caminho.startswith(prefixo):
            try:
                indice = int(caminho.removeprefix(prefixo))
            except ValueError:
                self._responder(404, "Câmera não encontrada.")
                return
            camera = self.server.cameras.get(indice)
            if camera is None:
                self._responder(404, "Câmera não encontrada.")
                return
            self._transmitir(camera, indice)
            return

        self._responder(404, "Página não encontrada.")

    def _transmitir(self, camera, indice):
        if camera.obter_frame() is None:
            self._responder(503, "A câmera ainda não está disponível.")
            return
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            while not self.server.parar.is_set():
                if self.server.cameras.get(indice) is not camera:
                    break
                frame = camera.obter_frame()
                if frame is None:
                    time.sleep(0.1)
                    continue
                altura, largura = frame.shape[:2]
                if largura > 1280:
                    frame = cv2.resize(frame, (1280, int(altura * 1280 / largura)))
                ok, imagem = cv2.imencode(
                    ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 80]
                )
                if ok:
                    dados = imagem.tobytes()
                    self.wfile.write(
                        b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                        + str(len(dados)).encode("ascii")
                        + b"\r\n\r\n"
                        + dados
                        + b"\r\n"
                    )
                    self.wfile.flush()
                time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, formato, *argumentos):
        print(f"Servidor de câmeras: {formato % argumentos}")


CAMINHOS_RTSP_YOOSEE = (
    "/live/ch00_0", "/live/ch00_1", "/live/ch0_0", "/live/ch0_1", "/live",
    "/ch0_0.264", "/ch0_1.264", "/ch00.264", "/ch01.264",
    "/stream1", "/stream0", "/stream/av0", "/videoMain", "/video1", "/h264", "/onvif1",
    "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
    "/cam/realmonitor?channel=1&subtype=00", "/cam/realmonitor?channel=1&subtype=01",
    "/Streaming/Channels/101", "/Streaming/Channels/102", "/Streaming/Channels/1",
    "/av_stream", "/0", "/1", "/mpeg4", "/media/video1",
)

def carregar_cameras_db():
    for caminho in [
        Path(__file__).resolve().parent / "cameras_ip_wifi_mundial.json",
        Path(__file__).resolve().parent / "cameras_db.json",
    ]:
        try:
            with open(caminho, "r", encoding="utf-8") as arquivo:
                return json.load(arquivo)
        except (OSError, json.JSONDecodeError):
            continue
    return None

def caminhos_por_fabricante(fabricante):
    db = carregar_cameras_db()
    if not db:
        return list(CAMINHOS_RTSP_YOOSEE)
    nome = (fabricante or "").lower()
    caminhos = []
    for item in db.get("fabricantes", []):
        if nome and nome in item.get("nome", "").lower():
            for padrao in item.get("rtsp_padrao", []):
                try:
                    if "@" in padrao and "/" in padrao:
                        parte = padrao.split("/", 3)[-1]
                        caminho = "/" + parte if not str(parte).startswith("/") else str(parte)
                        if caminho and caminho not in caminhos:
                            caminhos.append(caminho)
                except Exception:
                    pass
            break
    for c in CAMINHOS_RTSP_YOOSEE:
        if c not in caminhos:
            caminhos.append(c)
    return caminhos

def testar_caminhos_rtsp(ip, porta=554, timeout=2.0, fabricante=None):
    for caminho in caminhos_por_fabricante(fabricante):
        url = f"rtsp://{ip}:{porta}{caminho}"
        try:
            captura = cv2.VideoCapture(url)
            if captura.isOpened():
                ok, frame = captura.read()
                captura.release()
                if ok and frame is not None:
                    return url
            captura.release()
        except Exception:
            continue
    return None

class Camera:
    def __init__(self, id_camera, origem, rotulo):
        self.id = id_camera
        self.origem = origem  # Índice inteiro (USB) ou URL rtsp://... (rede).
        self.rotulo = rotulo
        self._frame = None
        self._erro = None
        self._lock = threading.Lock()
        self._parar = threading.Event()
        self.gravando = threading.Event()
        self.thread = threading.Thread(target=self._executar, daemon=True)
        self.thread.start()

    def _executar(self):
        captura = cv2.VideoCapture(self.origem)
        gravador = None
        falhas = 0
        try:
            if not captura.isOpened():
                with self._lock:
                    self._erro = (
                        "Câmera não encontrada. Confira o índice, o IP, "
                        "o caminho RTSP e as credenciais."
                    )
                return
            while not self._parar.is_set():
                ok, frame = captura.read()
                if not ok:
                    falhas += 1
                    if falhas >= 100 and self.obter_frame() is None:
                        with self._lock:
                            self._erro = (
                                "Sem sinal. Confira se a câmera está ligada "
                                "e o IP/caminho RTSP está correto."
                            )
                    time.sleep(0.1)
                    continue
                falhas = 0
                with self._lock:
                    self._frame = frame
                    self._erro = None

                if self.gravando.is_set():
                    if gravador is None:
                        nome = PASTA_CAPTURAS / (
                            f"camera_{rotulo_para_arquivo(self.rotulo)}"
                            f"_{datetime.now():%Y%m%d_%H%M%S}.avi"
                        )
                        altura, largura = frame.shape[:2]
                        gravador = cv2.VideoWriter(
                            str(nome), cv2.VideoWriter_fourcc(*"XVID"), 20.0,
                            (largura, altura),
                        )
                    if gravador.isOpened():
                        gravador.write(frame)
                elif gravador is not None:
                    gravador.release()
                    gravador = None
        finally:
            if gravador is not None:
                gravador.release()
            captura.release()

    def obter_frame(self):
        with self._lock:
            return self._frame.copy() if self._frame is not None else None

    def obter_erro(self):
        with self._lock:
            return self._erro

    def fechar(self):
        self.gravando.clear()
        self._parar.set()
        if self.thread.is_alive():
            self.thread.join(timeout=2)


class Aplicativo(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Monitoramento local por câmeras")
        self.geometry("1000x720")
        self.minsize(640, 450)
        self.cameras = {}
        self.paineis = {}
        self._proximo_id = 1
        self.busca_em_andamento = False
        self._resultado_busca = None
        self._resultado_auto = None
        self._resultado_localizar = None
        self._resultado_nvr = None
        self._resultado_cms = None
        self._canais_nvr = {}
        self.senha_web = carregar_ou_criar_senha()
        self.token_acesso = carregar_ou_criar_token()
        self.aparelhos = carregar_aparelhos()
        self.fila_trabalhos = queue.Queue()
        self.servidor_web = None
        self.thread_servidor_web = None
        self.hostname_servidor_web = None
        self.serve_ativo = False
        self.url_autorizacao_serve = None
        self.proxima_tentativa_https = 0.0
        self.thread_https = None
        self.resultado_https = None
        self.temporizador_credenciais = None
        self.enderecos_locais = self._detectar_enderecos_locais()
        self.protocol("WM_DELETE_WINDOW", self.fechar)

        controles = ttk.Frame(self, padding=10)
        controles.pack(fill="x")
        ttk.Label(controles, text="Índice da câmera:").pack(side="left")
        self.indice = tk.StringVar(value="0")
        self.entrada_indice = ttk.Entry(controles, textvariable=self.indice, width=6)
        self.entrada_indice.pack(side="left", padx=6)
        ttk.Button(controles, text="Adicionar câmera", command=self.adicionar_camera).pack(side="left")
        ttk.Label(controles, text=f"Arquivos: {PASTA_CAPTURAS.resolve()}").pack(side="left", padx=12)

        acesso = ttk.LabelFrame(self, text="Acesso seguro pelo celular (HTTPS + Tailscale)", padding=8)
        acesso.pack(fill="x", padx=10)
        ttk.Label(acesso, text="Link:").grid(row=0, column=0, sticky="w")
        self.link_web = tk.StringVar(value="Aguardando conexão segura...")
        ttk.Entry(acesso, textvariable=self.link_web, state="readonly").grid(
            row=0, column=1, sticky="ew", padx=6
        )
        self.botao_copiar_link = ttk.Button(
            acesso, text="Copiar link", command=self.copiar_link, state="disabled"
        )
        self.botao_copiar_link.grid(row=0, column=2)
        ttk.Label(acesso, text="Login:").grid(row=1, column=0, sticky="w")
        self.usuario_exibido = tk.StringVar(value="••••••••")
        ttk.Label(acesso, textvariable=self.usuario_exibido).grid(
            row=1, column=1, sticky="w", padx=6
        )
        ttk.Label(acesso, text="Senha:").grid(row=2, column=0, sticky="w")
        self.senha_exibida = tk.StringVar(value="••••••••••••")
        ttk.Label(acesso, textvariable=self.senha_exibida).grid(
            row=2, column=1, sticky="w", padx=6
        )
        self.botao_credenciais = ttk.Button(
            acesso, text="Autorizar e mostrar login e senha",
            command=self.alternar_credenciais,
        )
        self.botao_credenciais.grid(row=3, column=1, sticky="w", padx=6, pady=4)
        self.botao_ativar_https = ttk.Button(
            acesso, text="Ativar certificado HTTPS",
            command=self.abrir_autorizacao_serve, state="disabled",
        )
        self.botao_ativar_https.grid(row=3, column=2, padx=4, pady=4)
        self.estado_web = tk.StringVar(
            value="Conecte este computador e o celular à mesma VPN Tailscale."
        )
        ttk.Label(acesso, textvariable=self.estado_web).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(4, 0)
        )
        acesso.columnconfigure(1, weight=1)

        ssh = ttk.LabelFrame(self, text="Acesso remoto por túnel SSH (sem VPN)", padding=8)
        ssh.pack(fill="x", padx=10, pady=(6, 0))
        ttk.Label(ssh, text="Servidor SSH:").grid(row=0, column=0, sticky="w")
        self.entrada_ssh = ttk.Entry(ssh, width=20)
        self.entrada_ssh.insert(0, sugestao_ssh_destino())
        self.entrada_ssh.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(
            ssh, text="Colar", command=self.colar_destino_ssh
        ).grid(row=0, column=2, padx=(0, 6))
        ttk.Label(ssh, text="Porta local:").grid(row=0, column=3, sticky="w")
        self.entrada_porta_ssh = ttk.Entry(ssh, width=6)
        self.entrada_porta_ssh.insert(0, str(PORTA_WEB))
        self.entrada_porta_ssh.grid(row=0, column=4, sticky="w", padx=6)
        ttk.Button(
            ssh, text="Copiar comando", command=self.copiar_comando_ssh
        ).grid(row=0, column=5, padx=4)
        ttk.Button(
            ssh, text="Abrir no navegador", command=self.abrir_acesso_ssh
        ).grid(row=0, column=6, padx=4)
        ttk.Button(
            ssh, text="Copiar link", command=self.copiar_link_ssh
        ).grid(row=0, column=7, padx=4)
        self.comando_ssh = tk.StringVar(value="")
        ttk.Label(ssh, text="Chave SSH:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.entrada_chave_ssh = ttk.Entry(ssh, width=28)
        self.entrada_chave_ssh.grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=6, pady=(6, 0)
        )
        ttk.Label(
            ssh,
            text="(caminho da chave privada no computador que vai abrir o túnel; "
            "em branco, usa a chave padrão do SSH)",
        ).grid(row=1, column=3, columnspan=4, sticky="w", pady=(6, 0))

        ttk.Label(ssh, text="Usuário SSH:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.usuario_ssh = tk.StringVar(value=USUARIO_SSH_PADRAO)
        self.entrada_usuario_ssh = ttk.Entry(ssh, width=14, textvariable=self.usuario_ssh)
        self.entrada_usuario_ssh.grid(row=2, column=1, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(ssh, text="Senha:").grid(row=2, column=2, sticky="w", pady=(6, 0))
        self.senha_ssh = tk.StringVar(value="")
        self.entrada_senha_ssh = ttk.Entry(
            ssh, width=18, textvariable=self.senha_ssh, show="*"
        )
        self.entrada_senha_ssh.grid(row=2, column=3, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(
            ssh, text="Gerar senha", command=self.gerar_senha_ssh
        ).grid(row=2, column=4, padx=4, pady=(6, 0))
        self.botao_criar_usuario_ssh = ttk.Button(
            ssh, text="Criar/atualizar usuário", command=self.criar_usuario_ssh
        )
        self.botao_criar_usuario_ssh.grid(row=2, column=5, padx=4, pady=(6, 0))
        ttk.Button(
            ssh, text="Copiar senha", command=self.copiar_senha_ssh
        ).grid(row=2, column=6, padx=4, pady=(6, 0))
        self.estado_usuario_ssh = tk.StringVar(
            value=(
                "Conta para o túnel SSH: o sistema vai pedir a senha de "
                "administrador numa janela do próprio sistema."
            )
        )
        ttk.Label(ssh, textvariable=self.estado_usuario_ssh, justify="left").grid(
            row=3, column=0, columnspan=7, sticky="w", pady=(4, 0)
        )
        ttk.Entry(ssh, textvariable=self.comando_ssh, state="readonly").grid(
            row=4, column=0, columnspan=7, sticky="ew", pady=(6, 0)
        )
        self.estado_ssh = tk.StringVar(
            value="Rode o comando no computador/celular que vai ver as câmeras e "
            "abra o endereço local no navegador. O app precisa estar aberto aqui."
        )
        self.rotulo_estado_ssh = ttk.Label(
            ssh, textvariable=self.estado_ssh, justify="left"
        )
        self.rotulo_estado_ssh.grid(row=5, column=0, columnspan=7, sticky="w", pady=(4, 0))
        ssh.columnconfigure(1, weight=1)
        ssh.bind("<Configure>", self._ajustar_largura_ssh)
        self.entrada_ssh.bind("<KeyRelease>", self._atualizar_comando_ssh)
        self.entrada_porta_ssh.bind("<KeyRelease>", self._atualizar_comando_ssh)
        self.entrada_chave_ssh.bind("<KeyRelease>", self._atualizar_comando_ssh)

        aparelhos = ttk.LabelFrame(
            self, text="Aparelhos com acesso SSH (uma conta e uma chave por aparelho)",
            padding=8,
        )
        aparelhos.pack(fill="x", padx=10, pady=(6, 0))
        ttk.Label(aparelhos, text="Aparelho:").grid(row=0, column=0, sticky="w")
        self.nome_aparelho = tk.StringVar(value="")
        self.entrada_nome_aparelho = ttk.Entry(
            aparelhos, width=18, textvariable=self.nome_aparelho
        )
        self.entrada_nome_aparelho.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(aparelhos, text="Senha:").grid(row=0, column=2, sticky="w")
        self.senha_aparelho = tk.StringVar(value="")
        self.entrada_senha_aparelho = ttk.Entry(
            aparelhos, width=18, textvariable=self.senha_aparelho, show="*"
        )
        self.entrada_senha_aparelho.grid(row=0, column=3, sticky="w", padx=6)
        ttk.Button(
            aparelhos, text="Gerar senha", command=self.gerar_senha_aparelho
        ).grid(row=0, column=4, padx=4)
        self.botao_criar_aparelho = ttk.Button(
            aparelhos, text="Criar aparelho", command=self.criar_aparelho
        )
        self.botao_criar_aparelho.grid(row=0, column=5, padx=4)

        colunas = ("aparelho", "usuario", "chave", "situacao")
        self.lista_aparelhos = ttk.Treeview(
            aparelhos, columns=colunas, show="headings", height=4, selectmode="browse"
        )
        for coluna, titulo, largura in (
            ("aparelho", "Aparelho", 140),
            ("usuario", "Usuário SSH", 130),
            ("chave", "Chave", 190),
            ("situacao", "Situação", 120),
        ):
            self.lista_aparelhos.heading(coluna, text=titulo)
            self.lista_aparelhos.column(coluna, width=largura, anchor="w")
        self.lista_aparelhos.grid(
            row=1, column=0, columnspan=6, sticky="ew", pady=(8, 0)
        )
        self.lista_aparelhos.bind("<Double-1>", self.usar_aparelho_no_tunel)
        self.lista_aparelhos.bind("<Return>", self.usar_aparelho_no_tunel)

        acoes = ttk.Frame(aparelhos)
        acoes.grid(row=2, column=0, columnspan=6, sticky="w", pady=(6, 0))
        ttk.Button(
            acoes, text="Copiar chave privada", command=self.copiar_chave_aparelho
        ).pack(side="left", padx=(0, 4))
        ttk.Button(
            acoes, text="Copiar senha", command=self.copiar_senha_aparelho
        ).pack(side="left", padx=4)
        ttk.Button(
            acoes, text="Usar no túnel", command=self.usar_aparelho_no_tunel
        ).pack(side="left", padx=4)
        ttk.Button(
            acoes, text="Copiar comando", command=self.copiar_comando_aparelho
        ).pack(side="left", padx=4)
        ttk.Button(
            acoes, text="Remover aparelho", command=self.remover_aparelho
        ).pack(side="left", padx=4)
        self.estado_aparelhos = tk.StringVar(
            value=(
                "Cada aparelho tem conta, senha e chave próprias: revogar um "
                "não afeta os outros. Dê um nome (celular, notebook, tablet...)."
            )
        )
        ttk.Label(aparelhos, textvariable=self.estado_aparelhos, justify="left").grid(
            row=3, column=0, columnspan=6, sticky="w", pady=(4, 0)
        )
        aparelhos.columnconfigure(1, weight=1)

        rede = ttk.LabelFrame(self, text="Câmeras na rede local (Wi-Fi)", padding=8)
        rede.pack(fill="x", padx=10)
        self.botao_buscar = ttk.Button(
            rede, text="Buscar na rede (RTSP)", command=self.iniciar_busca_rede
        )
        self.botao_buscar.grid(row=0, column=0)
        self.botao_buscar_wifi = ttk.Button(
            rede, text="Buscar câmeras Wi-Fi", command=self.iniciar_busca_wifi_cameras
        )
        self.botao_buscar_wifi.grid(row=0, column=1, padx=(6, 0))
        self.botao_varredura_completa = ttk.Button(
            rede, text="Varredura completa (todos os dados)", command=self.iniciar_varredura_detalhada
        )
        self.botao_varredura_completa.grid(row=0, column=2, padx=(6, 0))
        ttk.Label(rede, text="Câmera:").grid(row=0, column=3, padx=(8, 2))
        self.combo_ip = ttk.Combobox(rede, width=28)
        self.combo_ip.grid(row=0, column=4)
        ttk.Label(rede, text="Caminho RTSP:").grid(row=0, column=5, padx=(8, 2))
        self.entrada_caminho = ttk.Entry(rede, width=14)
        self.entrada_caminho.insert(0, "/stream1")
        self.entrada_caminho.grid(row=0, column=6)
        ttk.Button(
            rede, text="Adicionar câmera de rede", command=self.adicionar_camera_rede
        ).grid(row=0, column=7, padx=6)
        ttk.Button(
            rede, text="Ler QR de imagem...", command=self.adicionar_por_qr
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Button(
            rede, text="Gerar QR para conectar câmera Wi-Fi",
            command=self.gerar_qr_config_wifi,
        ).grid(row=1, column=1, sticky="w", padx=(4, 0), pady=(6, 0))
        ttk.Button(
            rede, text="Detectar redes Wi-Fi", command=self.mostrar_redes_wifi
        ).grid(row=1, column=2, sticky="w", padx=(4, 0), pady=(6, 0))
        ttk.Button(
            rede, text="Ler QR da câmera (serial/config)", command=self.adicionar_por_qr
        ).grid(row=1, column=3, sticky="w", padx=(4, 0), pady=(6, 0))
        ttk.Label(rede, text="ID da câmera:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.entrada_id = ttk.Entry(rede)
        self.entrada_id.grid(row=2, column=1, columnspan=5, sticky="ew", padx=(4, 2), pady=(6, 0))
        ttk.Button(
            rede, text="Localizar na rede", command=self.localizar_camera_rede
        ).grid(row=2, column=6, columnspan=2, sticky="w", padx=6, pady=(6, 0))
        self.botao_auto = ttk.Button(
            rede,
            text="Configurar automaticamente (ONVIF + Rede)",
            command=self.configurar_automaticamente,
        )
        self.botao_auto.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Label(rede, text="NVR:").grid(row=4, column=0, sticky="w", pady=(6, 0))
        self.entrada_nvr = ttk.Entry(rede)
        self.entrada_nvr.grid(
            row=4, column=1, columnspan=4, sticky="ew", padx=(4, 2), pady=(6, 0)
        )
        ttk.Label(
            rede, text="(IP do gravador — lista os canais dele)"
        ).grid(row=4, column=6, sticky="w", pady=(6, 0))
        self.botao_nvr = ttk.Button(
            rede, text="Conectar ao NVR", command=self.conectar_nvr
        )
        self.botao_nvr.grid(row=4, column=7, padx=6, pady=(6, 0))
        self.botao_cms = ttk.Button(
            rede,
            text="Buscar pelo ID do CMS (UID)",
            command=self.buscar_por_id_cms,
        )
        self.botao_cms.grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(
            rede,
            text="ID/UID cadastrado no app CMS — procura portas de CMS e confere o serial.",
        ).grid(row=5, column=2, columnspan=6, sticky="w", pady=(6, 0))
        ttk.Button(
            rede, text="Copiar URL RTSP", command=self.copiar_url_camera
        ).grid(row=6, column=0, sticky="w", pady=(6, 0))
        ttk.Button(
            rede, text="Colar URL RTSP", command=self.colar_url_camera
        ).grid(row=6, column=1, sticky="w", padx=(4, 0), pady=(6, 0))
        ttk.Label(
            rede,
            text="Cole uma URL rtsp:// completa (com usuário e senha) para adicionar "
            "a câmera; Copiar URL RTSP leva a URL montada para a área de transferência.",
        ).grid(row=6, column=2, columnspan=6, sticky="w", pady=(6, 0))
        self.status_busca = tk.StringVar(
            value="Use 'Varredura completa (todos os dados)' para ver IP/MAC/ONVIF/perfis e configurar."
        )
        ttk.Label(rede, textvariable=self.status_busca).grid(
            row=3, column=3, columnspan=5, sticky="w", pady=(6, 0)
        )
        rede.columnconfigure(4, weight=1)
        rede.columnconfigure(5, weight=1)

        for campo in (
            self.entrada_indice,
            self.combo_ip,
            self.entrada_caminho,
            self.entrada_id,
            self.entrada_nvr,
            self.entrada_ssh,
            self.entrada_porta_ssh,
            self.entrada_chave_ssh,
            self.entrada_usuario_ssh,
            self.entrada_senha_ssh,
        ):
            self._ligar_menu_contexto(campo)

        self.grade = ttk.Frame(self, padding=8)
        self.grade.pack(fill="both", expand=True)
        self.mensagem = tk.StringVar(value="Adicione uma câmera. O índice 0 costuma ser a câmera padrão.")
        ttk.Label(self, textvariable=self.mensagem, padding=8).pack(fill="x")
        self.after(40, self.atualizar_imagens)
        self.after(0, self.atualizar_acesso_web)
        self.after(0, self._atualizar_comando_ssh)
        self.after(0, self._atualizar_estado_usuario_ssh)
        self.after(0, self._atualizar_lista_aparelhos)
        self.after(200, self._processar_trabalhos)

    def _ajustar_largura_ssh(self, evento):
        try:
            self.rotulo_estado_ssh.configure(wraplength=max(320, evento.width - 40))
        except tk.TclError:
            pass

    def _detectar_enderecos_locais(self):
        """Endereços que identificam esta máquina (para saber se o alvo do SSH é ela)."""
        enderecos = {"localhost", "127.0.0.1", "::1"}
        try:
            enderecos.add(socket.gethostname().lower())
        except OSError:
            pass
        ip_local = obter_ip_local()
        if ip_local:
            enderecos.add(ip_local.lower())
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                enderecos.add(str(info[4][0]).lower())
        except OSError:
            pass
        return enderecos

    def _porta_local_ssh(self):
        texto = self.entrada_porta_ssh.get().strip()
        if not texto.isdigit():
            raise ValueError("A porta local deve ser um número.")
        porta = int(texto)
        if not 1 <= porta <= 65535:
            raise ValueError("Porta local inválida (entre 1 e 65535).")
        return porta

    def _destino_ssh(self):
        """Devolve (destino, porta_local) já com a porta ajustada a conflitos."""
        destino = self.entrada_ssh.get().strip()
        if not destino:
            raise ValueError("Informe o servidor SSH (ex.: usuario@192.168.0.10).")
        porta_local = self._porta_local_ssh()
        if porta_local == PORTA_WEB and self._eh_esta_maquina(destino):
            porta_local = PORTA_WEB + 1
            self.entrada_porta_ssh.delete(0, "end")
            self.entrada_porta_ssh.insert(0, str(porta_local))
            self.estado_ssh.set(
                f"A porta {PORTA_WEB} já é usada por este app; o túnel usará "
                f"{porta_local} para não colidir."
            )
        return destino, porta_local

    def _eh_esta_maquina(self, destino):
        host = extrair_host_ssh(destino).lower().strip("[]")
        return host in self.enderecos_locais

    def _chave_ssh(self):
        """Caminho da chave privada a usar no comando (vazio = chave padrão)."""
        return self.entrada_chave_ssh.get().strip() or None

    def _atualizar_comando_ssh(self, evento=None):
        try:
            destino, porta_local = self._destino_ssh()
            self.comando_ssh.set(
                montar_comando_ssh(destino, porta_local, chave=self._chave_ssh())
            )
        except ValueError:
            self.comando_ssh.set("")

    def copiar_comando_ssh(self):
        try:
            destino, porta_local = self._destino_ssh()
            comando = montar_comando_ssh(
                destino, porta_local, chave=self._chave_ssh()
            )
        except ValueError as exc:
            messagebox.showerror("Túnel SSH", str(exc), parent=self)
            return
        self.comando_ssh.set(comando)
        copiar_texto(self, comando)
        self.estado_ssh.set(
            f"Comando copiado. Rode no computador/celular que vai ver as câmeras e "
            f"abra http://127.0.0.1:{porta_local} no navegador."
        )

    def _atualizar_estado_usuario_ssh(self, evento=None):
        """Mostra se a conta SSH do túnel já existe nesta máquina."""
        usuario = self.usuario_ssh.get().strip()
        if usuario and usuario_ssh_existe(usuario):
            self.estado_usuario_ssh.set(
                f"Conta \"{usuario}\" já existe nesta máquina. Para trocar a "
                "senha, digite a nova e clique em \"Criar/atualizar usuário\"."
            )
        else:
            self.estado_usuario_ssh.set(
                "Conta para o túnel SSH: o sistema vai pedir a senha de "
                "administrador numa janela do próprio sistema."
            )

    def gerar_senha_ssh(self):
        """Preenche o campo de senha com uma senha aleatória."""
        senha = senha_ssh_aleatoria(16)
        self.senha_ssh.set(senha)
        self.estado_usuario_ssh.set(
            "Senha gerada. Clique em \"Criar/atualizar usuário\" para aplicar "
            "(o sistema vai pedir a senha de administrador)."
        )

    def _processar_trabalhos(self):
        """Consome o que as threads deixaram na fila (sempre no thread do Tk)."""
        try:
            while True:
                item = self.fila_trabalhos.get_nowait()
                tipo = item[0]
                if tipo == "aparelho_criado":
                    self._aparelho_criado(*item[1:])
                elif tipo == "aparelho_removido":
                    self._aparelho_removido(*item[1:])
        except queue.Empty:
            pass
        self.after(200, self._processar_trabalhos)

    def _aparelho_selecionado(self):
        """Dados do aparelho marcado na lista (ou None)."""
        selecao = self.lista_aparelhos.selection()
        if not selecao:
            return None
        valores = self.lista_aparelhos.item(selecao[0]).get("values", ())
        if len(valores) < 2:
            return None
        usuario = valores[1]
        for aparelho in self.aparelhos:
            if aparelho.get("usuario") == usuario:
                return aparelho
        return None

    def _atualizar_lista_aparelhos(self):
        for item in self.lista_aparelhos.get_children():
            self.lista_aparelhos.delete(item)
        for aparelho in self.aparelhos:
            chave = Path(aparelho.get("chave", ""))
            situacao = (
                "ativo" if usuario_ssh_existe(aparelho.get("usuario", "")) else "sem conta"
            )
            self.lista_aparelhos.insert(
                "",
                "end",
                values=(
                    aparelho.get("nome", ""),
                    aparelho.get("usuario", ""),
                    chave.name,
                    situacao,
                ),
            )

    def gerar_senha_aparelho(self):
        senha = senha_ssh_aleatoria(16)
        self.senha_aparelho.set(senha)
        self.estado_aparelhos.set(
            "Senha gerada. Clique em \"Criar aparelho\" (o sistema vai pedir "
            "a senha de administrador)."
        )

    def copiar_senha_aparelho(self):
        aparelho = self._aparelho_selecionado()
        if not aparelho:
            messagebox.showinfo(
                "Aparelho", "Escolha um aparelho na lista.", parent=self
            )
            return
        copiar_texto(self, aparelho.get("senha", ""))
        self.estado_aparelhos.set(
            f"Senha de {aparelho.get('usuario')} copiada."
        )

    def copiar_chave_aparelho(self):
        aparelho = self._aparelho_selecionado()
        if not aparelho:
            messagebox.showinfo(
                "Aparelho", "Escolha um aparelho na lista.", parent=self
            )
            return
        chave = Path(aparelho.get("chave", ""))
        if not chave.exists():
            messagebox.showerror(
                "Aparelho", f"A chave {chave} não está mais neste computador.",
                parent=self,
            )
            return
        copiar_texto(self, chave.read_text(encoding="utf-8"))
        self.estado_aparelhos.set(
            f"Chave privada de {aparelho.get('usuario')} copiada. Cole no "
            "aparelho (Termius/Termux) e grave com permissão 600."
        )

    def usar_aparelho_no_tunel(self, evento=None):
        """Coloca o usuário e a chave do aparelho no quadro do túnel SSH."""
        aparelho = self._aparelho_selecionado()
        if not aparelho:
            if evento is None:
                messagebox.showinfo(
                    "Aparelho", "Escolha um aparelho na lista.", parent=self
                )
            return
        host = extrair_host_ssh(self.entrada_ssh.get().strip())
        if not host:
            host = sugestao_ssh_host()
        self.entrada_ssh.delete(0, "end")
        self.entrada_ssh.insert(0, f"{aparelho.get('usuario')}@{host}")
        self.entrada_chave_ssh.delete(0, "end")
        self.entrada_chave_ssh.insert(0, aparelho.get("chave", ""))
        self._atualizar_comando_ssh()
        self.estado_ssh.set(
            f"Túnel preparado para {aparelho.get('nome')} "
            f"({aparelho.get('usuario')}). Copie o comando e rode no aparelho."
        )
        self.estado_aparelhos.set(
            f"{aparelho.get('nome')} selecionado: usuário e chave já no túnel."
        )

    def copiar_comando_aparelho(self):
        aparelho = self._aparelho_selecionado()
        if not aparelho:
            messagebox.showinfo(
                "Aparelho", "Escolha um aparelho na lista.", parent=self
            )
            return
        self.usar_aparelho_no_tunel()
        self.copiar_comando_ssh()

    def criar_aparelho(self):
        nome = self.nome_aparelho.get().strip()
        if not nome:
            messagebox.showinfo(
                "Aparelho", "Dê um nome ao aparelho (celular, notebook...).",
                parent=self,
            )
            return
        senha = self.senha_aparelho.get() or senha_ssh_aleatoria(16)
        if len(senha) < 8:
            messagebox.showerror(
                "Aparelho", "A senha precisa ter ao menos 8 caracteres.", parent=self
            )
            return
        usuario = nome_usuario_aparelho(
            nome, [a.get("usuario") for a in self.aparelhos]
        )
        self.botao_criar_aparelho.configure(state="disabled")
        self.estado_aparelhos.set(
            "Aguarde a janela do sistema para autorizar a criação da conta..."
        )

        def trabalho():
            erro = None
            caminho = chave_aparelho(usuario)
            try:
                gerar_chave_para(caminho, f"cameras-{usuario}")
                criar_usuario_ssh_sistema(usuario, senha, caminho)
            except Exception as exc:  # noqa: BLE001 - erro vem do sistema/polkit
                erro = exc
            self.fila_trabalhos.put(
                ("aparelho_criado", nome, usuario, senha, str(caminho), erro)
            )

        threading.Thread(target=trabalho, daemon=True).start()

    def _aparelho_criado(self, nome, usuario, senha, caminho, erro):
        self.botao_criar_aparelho.configure(state="normal")
        if erro is not None:
            self.estado_aparelhos.set(f"Não foi possível criar o aparelho: {erro}")
            messagebox.showerror("Aparelho", str(erro), parent=self)
            return
        self.aparelhos.append(
            {
                "nome": nome,
                "usuario": usuario,
                "senha": senha,
                "chave": caminho,
                "criado_em": time.strftime("%Y-%m-%d %H:%M"),
            }
        )
        salvar_aparelhos(self.aparelhos)
        self._atualizar_lista_aparelhos()
        self.senha_aparelho.set(senha)
        self.nome_aparelho.set("")
        self.estado_aparelhos.set(
            f"Conta \"{usuario}\" criada para {nome}. Copie a chave privada "
            "(botão abaixo) e leve ao aparelho; a senha também funciona."
        )

    def remover_aparelho(self):
        aparelho = self._aparelho_selecionado()
        if not aparelho:
            messagebox.showinfo(
                "Aparelho", "Escolha um aparelho na lista.", parent=self
            )
            return
        usuario = aparelho.get("usuario", "")
        if not messagebox.askyesno(
            "Remover aparelho",
            f"Remover a conta \"{usuario}\"?\n\n"
            "O aparelho perde o acesso às câmeras na hora.",
            parent=self,
        ):
            return
        self.estado_aparelhos.set(
            "Aguarde a janela do sistema para autorizar a remoção..."
        )

        def trabalho():
            erro = None
            try:
                remover_usuario_ssh_sistema(usuario)
            except Exception as exc:  # noqa: BLE001
                erro = exc
            self.fila_trabalhos.put(("aparelho_removido", usuario, erro))

        threading.Thread(target=trabalho, daemon=True).start()

    def _aparelho_removido(self, usuario, erro):
        if erro is not None:
            self.estado_aparelhos.set(f"Não foi possível remover: {erro}")
            messagebox.showerror("Aparelho", str(erro), parent=self)
            return
        self.aparelhos = [
            a for a in self.aparelhos if a.get("usuario") != usuario
        ]
        salvar_aparelhos(self.aparelhos)
        self._atualizar_lista_aparelhos()
        self.estado_aparelhos.set(
            f"Conta \"{usuario}\" removida: aquele aparelho não acessa mais as câmeras."
        )

    def copiar_senha_ssh(self):
        senha = self.senha_ssh.get()
        if not senha:
            messagebox.showinfo(
                "Senha SSH", "Gere ou digite uma senha primeiro.", parent=self
            )
            return
        copiar_texto(self, senha)
        self.estado_usuario_ssh.set(
            "Senha copiada. É com ela que o celular entra no SSH."
        )

    def criar_usuario_ssh(self):
        """Cria (ou ajusta) a conta SSH do túnel, com a senha digitada aqui."""
        usuario = self.usuario_ssh.get().strip()
        senha = self.senha_ssh.get()
        if not senha:
            senha = senha_ssh_aleatoria(16)
            self.senha_ssh.set(senha)
        try:
            chave = garantir_chave_cameras()
            criar_usuario_ssh_sistema(usuario, senha, chave)
        except Exception as exc:  # noqa: BLE001 - erro vem do sistema/polkit
            self.estado_usuario_ssh.set(f"Não foi possível criar o usuário: {exc}")
            messagebox.showerror("Usuário SSH", str(exc), parent=self)
            return
        self.estado_usuario_ssh.set(
            f"Usuário \"{usuario}\" pronto: senha definida e chave "
            "autorizada. Use esse usuário no campo \"Servidor SSH\"."
        )
        # Se o campo de destino ainda não tem usuário, sugere o novo.
        destino = self.entrada_ssh.get().strip()
        if not destino or "@" not in destino:
            host = extrair_host_ssh(destino) or sugestao_ssh_host()
            self.entrada_ssh.delete(0, "end")
            self.entrada_ssh.insert(0, f"{usuario}@{host}")
            self._atualizar_comando_ssh()

    def colar_destino_ssh(self):
        """Cola o destino do túnel: aceita `usuario@host` ou um comando ssh pronto."""
        texto = obter_texto_colado(self).strip()
        if not texto:
            self.estado_ssh.set("A área de transferência está vazia.")
            return
        analisado = analisar_comando_ssh(texto)
        if analisado is not None:
            destino, porta_local, chave = analisado
            self.entrada_ssh.delete(0, "end")
            self.entrada_ssh.insert(0, destino)
            if porta_local:
                self.entrada_porta_ssh.delete(0, "end")
                self.entrada_porta_ssh.insert(0, str(porta_local))
            if chave:
                self.entrada_chave_ssh.delete(0, "end")
                self.entrada_chave_ssh.insert(0, chave)
            self._atualizar_comando_ssh()
            self.estado_ssh.set(
                f"Destino colado do comando SSH ({destino}). Confira e copie o comando."
            )
            return
        try:
            montar_comando_ssh(texto)
        except ValueError as exc:
            messagebox.showerror(
                "Colar destino",
                f"O texto colado não é um destino SSH válido.\n\n{exc}",
                parent=self,
            )
            return
        self.entrada_ssh.delete(0, "end")
        self.entrada_ssh.insert(0, texto)
        self._atualizar_comando_ssh()
        self.estado_ssh.set("Destino colado.")

    def _menu_contexto(self, widget):
        """Menu de contexto (copiar/colar) dos campos de texto."""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(
            label="Copiar", command=lambda: self._acao_contexto(widget, "copiar")
        )
        menu.add_command(
            label="Colar", command=lambda: self._acao_contexto(widget, "colar")
        )
        menu.add_command(
            label="Selecionar tudo",
            command=lambda: self._acao_contexto(widget, "selecionar"),
        )
        menu.add_separator()
        menu.add_command(
            label="Limpar", command=lambda: self._acao_contexto(widget, "limpar")
        )
        return menu

    def _acao_contexto(self, widget, acao):
        if acao == "copiar":
            texto = widget.get()
            if isinstance(texto, str) and texto:
                copiar_texto(self, texto)
        elif acao == "colar":
            texto = obter_texto_colado(self)
            if not texto:
                return
            if isinstance(widget, ttk.Combobox):
                widget.set(texto.strip())
            else:
                widget.delete(0, "end")
                widget.insert(0, texto)
            widget.icursor("end")
        elif acao == "selecionar":
            widget.selection_range(0, "end")
            widget.icursor("end")
        elif acao == "limpar":
            if isinstance(widget, ttk.Combobox):
                widget.set("")
            else:
                widget.delete(0, "end")

    def _mostrar_menu_contexto(self, evento, widget):
        menu = self._menu_contexto(widget)
        try:
            menu.tk_popup(evento.x_root, evento.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _ligar_menu_contexto(self, widget):
        widget.bind(
            "<Button-3>", lambda evento: self._mostrar_menu_contexto(evento, widget)
        )
        if sys.platform == "darwin":
            # No macOS o botão secundário é o Button-2 (o do meio colaria).
            widget.bind(
                "<Button-2>", lambda evento: self._mostrar_menu_contexto(evento, widget)
            )

    def link_de_acesso(self, base=None):
        """Link que abre as câmeras já autenticado (sem pedir login)."""
        if base is None:
            base = f"http://127.0.0.1:{PORTA_WEB}"
        base = base.rstrip("/")
        return f"{base}/?acesso={self.token_acesso}"

    def abrir_acesso_ssh(self):
        try:
            _, porta_local = self._destino_ssh()
        except ValueError as exc:
            messagebox.showerror("Túnel SSH", str(exc), parent=self)
            return
        url = self.link_de_acesso(f"http://127.0.0.1:{porta_local}")
        if not webbrowser.open(url):
            self.estado_ssh.set(f"Abra manualmente no navegador: {url}")

    def copiar_link_ssh(self):
        """Link local (com acesso) para abrir no outro computador/celular."""
        try:
            _, porta_local = self._destino_ssh()
        except ValueError as exc:
            messagebox.showerror("Túnel SSH", str(exc), parent=self)
            return
        link = self.link_de_acesso(f"http://127.0.0.1:{porta_local}")
        copiar_texto(self, link)
        self.estado_ssh.set(
            f"Link copiado ({link}). Abra no aparelho que vai ver as câmeras, "
            "depois de subir o túnel SSH — ele entra direto, sem pedir login."
        )

    def copiar_link(self):
        link = self.link_web.get()
        if not (link.startswith("https://") or link.startswith("http://")):
            self.estado_web.set("O link ainda não está disponível.")
            return
        link = self.link_de_acesso(link)
        copiar_texto(self, link)
        if link.startswith("https://"):
            self.estado_web.set(
                "Link com acesso automático copiado (não vai pedir login). "
                "Conecte o celular à VPN e abra o link."
            )
        else:
            self.estado_web.set(
                "Link local com acesso automático copiado. Para ver de outro "
                "computador, use o túnel SSH abaixo."
            )

    def alternar_credenciais(self):
        if self.temporizador_credenciais is not None:
            self.ocultar_credenciais()
            return
        if ARQUIVO_SENHA_SEGURANCA.exists():
            senha_seg = simpledialog.askstring(
                "Autorizar credenciais",
                "Digite a senha de segurança para revelar o login e a senha:",
                show="*",
                parent=self,
            )
            if senha_seg is None:
                return
            try:
                autorizado = verificar_senha_seguranca(senha_seg)
            except ValueError as exc:
                messagebox.showerror("Senha de segurança", str(exc), parent=self)
                return
            if not autorizado:
                messagebox.showerror(
                    "Acesso negado", "A senha de segurança está incorreta.", parent=self
                )
                return
        else:
            senha_seg = simpledialog.askstring(
                "Criar senha de segurança",
                "Crie uma senha de segurança com pelo menos 12 caracteres. "
                "Ela será necessária para mostrar o login e a senha:",
                show="*",
                parent=self,
            )
            if senha_seg is None:
                return
            if len(senha_seg) < 12:
                messagebox.showerror(
                    "Senha muito curta",
                    "Use pelo menos 12 caracteres.",
                    parent=self,
                )
                return
            confirmacao = simpledialog.askstring(
                "Confirmar senha de segurança",
                "Digite novamente a senha de segurança:",
                show="*",
                parent=self,
            )
            if confirmacao is None:
                return
            if not secrets.compare_digest(senha_seg, confirmacao):
                messagebox.showerror(
                    "Senhas diferentes",
                    "As senhas informadas não coincidem.",
                    parent=self,
                )
                return
            try:
                salvar_senha_seguranca(senha_seg)
            except OSError as exc:
                messagebox.showerror(
                    "Falha ao salvar senha",
                    f"Não foi possível salvar a senha de segurança: {exc}",
                    parent=self,
                )
                return

        self.usuario_exibido.set(USUARIO_WEB)
        self.senha_exibida.set(self.senha_web)
        self.botao_credenciais.configure(text="Ocultar login e senha")
        self.temporizador_credenciais = self.after(
            60_000, self.ocultar_credenciais
        )

    def ocultar_credenciais(self):
        if self.temporizador_credenciais is not None:
            try:
                self.after_cancel(self.temporizador_credenciais)
            except tk.TclError:
                pass
            self.temporizador_credenciais = None
        self.usuario_exibido.set("••••••••")
        self.senha_exibida.set("••••••••••••")
        self.botao_credenciais.configure(text="Autorizar e mostrar login e senha")

    def abrir_autorizacao_serve(self):
        if self.url_autorizacao_serve is None:
            return
        if not webbrowser.open(self.url_autorizacao_serve):
            self.estado_web.set(
                f"Abra este endereço para autorizar o HTTPS: {self.url_autorizacao_serve}"
            )

    def atualizar_acesso_web(self):
        if self.resultado_https is not None:
            hostname, ativo, mensagem, url_autorizacao = self.resultado_https
            self.resultado_https = None
            self.thread_https = None
            if hostname == self.hostname_servidor_web:
                self.serve_ativo = ativo
                self.url_autorizacao_serve = url_autorizacao
                self.proxima_tentativa_https = time.monotonic() + 30
                if ativo:
                    self.link_web.set(f"https://{hostname}")
                    self.botao_copiar_link.configure(state="normal")
                    self.botao_ativar_https.configure(state="disabled")
                    self.estado_web.set(mensagem)
                else:
                    self.link_web.set("Aguardando ativação do HTTPS")
                    self.botao_copiar_link.configure(state="disabled")
                    self.botao_ativar_https.configure(state="normal")
                    self.estado_web.set(mensagem)

        try:
            resultado = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except FileNotFoundError:
            identidade = None
            estado = "Tailscale não está instalado."
        except subprocess.TimeoutExpired:
            identidade = None
            estado = "O serviço Tailscale não respondeu."
        else:
            identidade = None
            if resultado.returncode == 0:
                try:
                    dados = json.loads(resultado.stdout)
                    self_tailscale = dados.get("Self", {})
                    hostname = self_tailscale.get("DNSName", "").rstrip(".")
                    node_id = self_tailscale.get("ID", "")
                    conectado = (
                        dados.get("BackendState") == "Running"
                        and self_tailscale.get("Online") is True
                        and hostname.endswith(".ts.net")
                        and node_id.isalnum()
                    )
                except (json.JSONDecodeError, AttributeError):
                    conectado = False
                if conectado:
                    identidade = (hostname, node_id)

            if identidade is None:
                detalhe = resultado.stderr.strip()
                estado = (
                    "Conecte este computador à VPN Tailscale para disponibilizar o acesso."
                )
                if detalhe:
                    estado = f"{estado} {detalhe}"
            else:
                hostname, _ = identidade
                estado = "HTTPS privado ativo; conecte o celular à mesma VPN Tailscale."

        if identidade is None:
            # Sem Tailscale o servidor continua no ar em 127.0.0.1: é ele que o
            # túnel SSH encaminha para o outro computador.
            if not self._iniciar_servidor_web():
                self.link_web.set("Não foi possível iniciar o servidor")
                self.botao_copiar_link.configure(state="disabled")
                self.botao_ativar_https.configure(state="disabled")
                self.after(5000, self.atualizar_acesso_web)
                return
            self.link_web.set(f"http://127.0.0.1:{PORTA_WEB}")
            self.botao_copiar_link.configure(state="normal")
            self.botao_ativar_https.configure(state="disabled")
            self.estado_web.set(
                f"{estado} Para ver de outro computador, use o túnel SSH abaixo."
            )
        else:
            hostname, node_id = identidade
            if hostname != self.hostname_servidor_web:
                self._parar_servidor_web()
                if not self._iniciar_servidor_web():
                    self.link_web.set("Não foi possível iniciar o servidor")
                    self.botao_copiar_link.configure(state="disabled")
                    self.estado_web.set("Falha ao iniciar o servidor de câmeras.")
                    self.after(5000, self.atualizar_acesso_web)
                    return
                self.hostname_servidor_web = hostname
                self.link_web.set("Solicitando certificado HTTPS...")
                self.botao_copiar_link.configure(state="disabled")
            elif self.serve_ativo:
                self.link_web.set(f"https://{hostname}")
                self.botao_copiar_link.configure(state="normal")
            if (
                self.servidor_web is not None
                and self.hostname_servidor_web == hostname
                and not self.serve_ativo
                and self.thread_https is None
                and time.monotonic() >= self.proxima_tentativa_https
            ):
                self._iniciar_https(hostname, node_id)
            if self.serve_ativo:
                self.estado_web.set(estado)
        self.after(5000, self.atualizar_acesso_web)

    def _iniciar_https(self, hostname, node_id):
        self.thread_https = threading.Thread(
            target=self._configurar_https,
            args=(hostname, node_id),
            name="configurar-https-tailscale",
            daemon=True,
        )
        self.thread_https.start()

    def _configurar_https(self, hostname, node_id):
        url_autorizacao = (
            f"https://login.tailscale.com/f/serve?node={node_id}"
            if node_id.isalnum()
            else None
        )
        try:
            configuracao = subprocess.run(
                ["tailscale", "serve", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if configuracao.returncode != 0:
                raise RuntimeError(
                    configuracao.stderr.strip()
                    or "Não foi possível verificar as rotas Tailscale existentes."
                )
            rotas = json.loads(configuracao.stdout or "{}")
            if rotas and str(PORTA_WEB) not in json.dumps(rotas):
                raise RuntimeError(
                    "Já existe outra configuração do Tailscale Serve. "
                    "Ela não foi alterada para proteger os serviços existentes."
                )
            resultado = subprocess.run(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=443",
                    f"http://127.0.0.1:{PORTA_WEB}",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except FileNotFoundError:
            mensagem = "O comando Tailscale não foi encontrado."
            ativo = False
        except (RuntimeError, json.JSONDecodeError) as exc:
            mensagem = str(exc)
            ativo = False
        except subprocess.TimeoutExpired:
            mensagem = (
                "Aguardando autorização do Tailscale para ativar o HTTPS. "
                "Use o botão para abrir a página de autorização."
            )
            ativo = False
        else:
            ativo = resultado.returncode == 0
            mensagem = (
                "Certificado HTTPS válido ativo no endereço privado. "
                "Conecte o celular à mesma VPN."
                if ativo
                else resultado.stderr.strip() or resultado.stdout.strip()
                or "O Tailscale não conseguiu ativar HTTPS."
            )
        self.resultado_https = (hostname, ativo, mensagem, url_autorizacao)

    def _iniciar_servidor_web(self):
        """Sobe o servidor HTTP local (127.0.0.1) usado pelo Tailscale e pelo túnel SSH."""
        if self.servidor_web is not None:
            return True
        try:
            self.servidor_web = ServidorCameras(
                self.cameras, self.senha_web, self.token_acesso
            )
            self.thread_servidor_web = threading.Thread(
                target=self.servidor_web.serve_forever,
                name="servidor-cameras",
                daemon=True,
            )
            self.thread_servidor_web.start()
        except OSError as exc:
            self.servidor_web = None
            self.thread_servidor_web = None
            self.estado_web.set(f"Falha ao iniciar o servidor: {exc}")
            return False
        return True

    def _parar_servidor_web(self):
        self.serve_ativo = False
        self.url_autorizacao_serve = None
        self.botao_ativar_https.configure(state="disabled")
        if self.servidor_web is not None:
            self.servidor_web.parar.set()
            self.servidor_web.shutdown()
            self.servidor_web.server_close()
            if self.thread_servidor_web is not None:
                self.thread_servidor_web.join(timeout=1)
            self.servidor_web = None
            self.thread_servidor_web = None
        self.hostname_servidor_web = None

    def adicionar_camera(self):
        try:
            indice = int(self.indice.get())
            if indice < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Índice inválido", "Informe um inteiro igual ou maior que zero.")
            return
        self._adicionar_camera_interna(indice, str(indice))

    def iniciar_busca_rede(self):
        if self.busca_em_andamento:
            return
        ip_local = obter_ip_local()
        if ip_local is None:
            self.status_busca.set(
                "Não foi possível identificar a rede local (Wi-Fi/LAN). "
                "Digite o IP da câmera manualmente."
            )
            return
        self.busca_em_andamento = True
        self._resultado_busca = None
        self.botao_buscar.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.status_busca.set(f"Buscando câmeras RTSP em {ip_local}/24 ...")
        threading.Thread(
            target=self._executar_busca_rede, args=(ip_local,), daemon=True
        ).start()
        self.after(500, self._aguardar_busca_rede)

    def _executar_busca_rede(self, ip_local):
        try:
            self._resultado_busca = buscar_cameras_rede(ip_local)
        except OSError as exc:
            self._resultado_busca = f"falha: {exc}"

    def _aguardar_busca_rede(self):
        if self._resultado_busca is None:
            self.after(500, self._aguardar_busca_rede)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="normal")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="normal")
        self.botao_auto.configure(state="normal")
        resultado = self._resultado_busca
        self._resultado_busca = None
        if isinstance(resultado, str):
            self.status_busca.set(
                f"Falha na busca: {resultado.removeprefix('falha: ')}"
            )
            return
        if not resultado:
            self.status_busca.set(
                "Nenhuma câmera RTSP encontrada. Tente 'Varredura completa (todos os dados)' ou "
                "'Buscar câmeras Wi-Fi'."
            )
            return
        rotulos = [
            host if portas[0] == 554 else f"{host}:{portas[0]}"
            for host, portas in resultado
        ]
        self.combo_ip.configure(values=rotulos)
        self.combo_ip.set(rotulos[0])
        self.status_busca.set(
            f"{len(rotulos)} candidata(s). Escolha o IP (ou digite "
            "rtsp://usuario:senha@ip/caminho), ajuste o caminho e adicione."
        )

    def iniciar_busca_wifi_cameras(self):
        if self.busca_em_andamento:
            return
        ip_local = obter_ip_local()
        if ip_local is None:
            self.status_busca.set(
                "Não foi possível identificar a rede local (Wi-Fi/LAN). "
                "Digite o IP da câmera manualmente."
            )
            return
        self.busca_em_andamento = True
        self._resultado_busca = None
        self.botao_buscar.configure(state="disabled")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="disabled")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.status_busca.set(f"Buscando câmeras Yoosee/Gwell na rede {ip_local}/24 (ARP + portas)...")
        threading.Thread(
            target=self._executar_busca_rede, args=(ip_local,), daemon=True
        ).start()
        self.after(500, self._aguardar_busca_rede)

    def iniciar_varredura_detalhada(self):
        if self.busca_em_andamento:
            return
        ip_local = obter_ip_local()
        if ip_local is None:
            self.status_busca.set(
                "Não foi possível identificar a rede local (Wi-Fi/LAN)."
            )
            return
        usuario = simpledialog.askstring(
            "Varredura completa",
            "Usuário das câmeras (deixe em branco para tentar sem senha):",
            parent=self,
        )
        if usuario is None:
            return
        senha = simpledialog.askstring(
            "Varredura completa",
            "Senha das câmeras (deixe em branco se não houver):",
            show="*",
            parent=self,
        )
        if senha is None:
            return
        self.busca_em_andamento = True
        self._resultado_detalhado = None
        self.botao_buscar.configure(state="disabled")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="disabled")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.status_busca.set(f"Varredura completa de {ip_local}/24 - coletando todos os dados...")
        threading.Thread(
            target=self._executar_varredura_detalhada,
            args=(ip_local, usuario.strip(), senha),
            daemon=True,
        ).start()
        self.after(500, self._aguardar_varredura_detalhada)

    def _executar_varredura_detalhada(self, ip_local, usuario, senha):
        try:
            self._resultado_detalhado = varredura_detalhada_rede(ip_local, usuario, senha)
        except Exception as exc:
            self._resultado_detalhado = f"falha: {exc}"

    def _aguardar_varredura_detalhada(self):
        if self._resultado_detalhado is None:
            self.after(500, self._aguardar_varredura_detalhada)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="normal")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="normal")
        self.botao_auto.configure(state="normal")
        resultado = self._resultado_detalhado
        self._resultado_detalhado = None
        if isinstance(resultado, str):
            self.status_busca.set(f"Falha na varredura: {resultado.removeprefix('falha: ')}")
            return
        if not resultado:
            self.status_busca.set("Nenhum dispositivo com cara de câmera encontrado na rede.")
            return
        self.mostrar_janela_varredura(resultado)

    def localizar_camera_rede(self):
        """Localiza uma câmera pelo ID/serial, IP ou nome de host."""
        if self.busca_em_andamento:
            return
        texto = self.entrada_id.get().strip()
        if not texto:
            self.status_busca.set(
                "Informe o ID da câmera (etiqueta/rótulo), o IP ou o nome de host."
            )
            return
        self.busca_em_andamento = True
        self._resultado_localizar = None
        self.botao_buscar.configure(state="disabled")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="disabled")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        if hasattr(self, "botao_nvr"):
            self.botao_nvr.configure(state="disabled")
        if hasattr(self, "botao_cms"):
            self.botao_cms.configure(state="disabled")
        self.status_busca.set(f"Localizando “{texto}” na rede local ...")
        threading.Thread(
            target=self._executar_localizacao,
            args=(texto, obter_ip_local()),
            daemon=True,
        ).start()
        self.after(500, self._aguardar_localizacao)

    def _executar_localizacao(self, texto, ip_local):
        try:
            self._resultado_localizar = localizar_camera(texto, ip_local)
        except OSError as exc:
            self._resultado_localizar = ([], f"falha: {exc}")

    def _aguardar_localizacao(self):
        if self._resultado_localizar is None:
            self.after(500, self._aguardar_localizacao)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="normal")
        if hasattr(self, "botao_varredura_completa"):
            self.botao_varredura_completa.configure(state="normal")
        self.botao_auto.configure(state="normal")
        if hasattr(self, "botao_nvr"):
            self.botao_nvr.configure(state="normal")
        if hasattr(self, "botao_cms"):
            self.botao_cms.configure(state="normal")
        candidatos, erro = self._resultado_localizar
        self._resultado_localizar = None
        if isinstance(candidatos, str):
            self.status_busca.set(
                f"Falha ao localizar: {candidatos.removeprefix('falha: ')}"
            )
            return
        if not candidatos:
            self.status_busca.set(erro or "Câmera não encontrada.")
            return
        rotulos = [
            f"{c['ip']}:{c['portas'][0]}" if c["portas"][0] != 554 else c["ip"]
            for c in candidatos
        ]
        if len(rotulos) == 1:
            rotulo = rotulos[0]
        else:
            self.combo_ip.configure(values=rotulos)
            rotulo = rotulos[0]
        self.combo_ip.set(rotulo)
        self._canais_nvr[rotulo] = f"rtsp://{candidatos[0]['ip']}:{candidatos[0]['portas'][0]}"
        if candidatos[0].get("url"):
            self.entrada_id.delete(0, "end")
            self.entrada_id.insert(0, candidatos[0]["url"])
            self._canais_nvr[rotulo] = candidatos[0]["url"]
        detalhe = "ONVIF" if candidatos[0]["onvif"] else "RTSP/YOSEEE"
        nome = candidatos[0].get("nome")
        extra = f" — {nome}" if nome else ""
        auto = " — URL RTSP detectado automaticamente" if candidatos[0].get("auto") else ""
        self.status_busca.set(
            f"Câmera encontrada: {rotulo} ({detalhe}){extra}{auto}. Clique em "
            "Adicionar câmera de rede."
        )

    def configurar_automaticamente(self):
        """Descobre câmeras ONVIF + varre toda a rede e adiciona sozinho o stream de cada uma."""
        if self.busca_em_andamento:
            return
        ip_local = obter_ip_local()
        if ip_local is None:
            self.status_busca.set(
                "Não foi possível identificar a rede local (Wi-Fi/LAN)."
            )
            return
        usuario = simpledialog.askstring(
            "Configuração automática",
            "Usuário das câmeras (deixe em branco para tentar sem senha):",
            parent=self,
        )
        if usuario is None:
            return
        senha = simpledialog.askstring(
            "Configuração automática",
            "Senha das câmeras (a mesma da câmera/app):",
            show="*",
            parent=self,
        )
        if senha is None:
            return
        self.busca_em_andamento = True
        self._resultado_auto = None
        self.botao_buscar.configure(state="disabled")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.status_busca.set(
            "Varredura completa da rede + ONVIF para configurar câmeras automaticamente..."
        )
        threading.Thread(
            target=self._executar_config_automatica_completa,
            args=(ip_local, usuario.strip(), senha),
            daemon=True,
        ).start()
        self.after(500, self._aguardar_config_automatica)

    def _executar_config_automatica_completa(self, ip_local, usuario, senha):
        try:
            resultados = []
            vistos = set()

            # 1) ONVIF WS-Discovery
            try:
                dispositivos = descobrir_onvif(ip_local)
                for dispositivo in dispositivos:
                    ip_dev = dispositivo["ip"]
                    if ip_dev in vistos:
                        continue
                    vistos.add(ip_dev)
                    url_stream = None
                    erro = None
                    for url in dispositivo["urls"]:
                        url_stream, erro = obter_uri_rtsp(url, usuario, senha)
                        if url_stream:
                            break
                    if not dispositivo["urls"] and not url_stream:
                        erro = "a descoberta não informou o endereço ONVIF"
                    resultados.append((dispositivo, url_stream, erro, "ONVIF"))
            except Exception:
                pass

            # 2) Varredura completa da rede por portas RTSP/Yoosee
            try:
                prefixo = ".".join(ip_local.split(".")[:3])
                portas_busca = tuple(dict.fromkeys([*PORTAS_RTSP, *PORTAS_YOOSEE]))
                abertas = _varrer_portas(prefixo, portas_busca, excluir=ip_local)
                for ip, portas in abertas.items():
                    if ip in vistos:
                        continue
                    vistos.add(ip)
                    url_stream = testar_caminhos_rtsp(ip, 554) or testar_caminhos_rtsp(ip, portas[0] if portas else 554)
                    if not url_stream and portas:
                        for p in portas:
                            if p == 554:
                                continue
                            url_stream = testar_caminhos_rtsp(ip, p)
                            if url_stream:
                                break
                    dispositivo = {"ip": ip, "urls": [], "nome": None}
                    resultados.append((dispositivo, url_stream, None if url_stream else "não encontrou caminho RTSP", "VARREDURA"))
            except Exception:
                pass

            self._resultado_auto = resultados
        except OSError as exc:
            self._resultado_auto = f"falha: {exc}"

    def _executar_config_automatica(self, ip_local, usuario, senha):
        # Mantido por compatibilidade
        self._executar_config_automatica_completa(ip_local, usuario, senha)

    def _aguardar_config_automatica(self):
        if self._resultado_auto is None:
            self.after(500, self._aguardar_config_automatica)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        if hasattr(self, "botao_buscar_wifi"):
            self.botao_buscar_wifi.configure(state="normal")
        self.botao_auto.configure(state="normal")
        resultado = self._resultado_auto
        self._resultado_auto = None
        if isinstance(resultado, str):
            self.status_busca.set(
                f"Falha na configuração automática: "
                f"{resultado.removeprefix('falha: ')}"
            )
            return
        if not resultado:
            self.status_busca.set(
                "Nenhuma câmera encontrada na varredura completa. Confira se estão "
                "ligadas e na mesma rede Wi-Fi/LAN."
            )
            return
        configuradas = 0
        falhas = []
        for dispositivo, url_stream, erro, origem in resultado:
            if url_stream:
                rotulo = (
                    f"{dispositivo.get('nome')} ({dispositivo['ip']}) [{origem}]"
                    if dispositivo.get('nome')
                    else f"{dispositivo['ip']} [{origem}]"
                )
                self._adicionar_camera_interna(url_stream, rotulo)
                configuradas += 1
            elif erro:
                falhas.append(f"{dispositivo['ip']} [{origem}]: {erro}")
        partes = [f"{configuradas} câmera(s) configurada(s) automaticamente (varredura + ONVIF)."]
        if falhas:
            partes.append(
                "Falhas: " + "; ".join(falhas[:4])
                + ("..." if len(falhas) > 4 else "")
            )
        self.status_busca.set(" ".join(partes))

    def conectar_nvr(self):
        """Conecta a um NVR pelo IP e lista os canais (streams) dele."""
        if self.busca_em_andamento:
            return
        endereco = self.entrada_nvr.get().strip()
        if not endereco:
            self.status_busca.set(
                "Informe o IP do NVR (ex.: 192.168.0.10) para listar os canais."
            )
            return
        usuario = simpledialog.askstring(
            "Conectar ao NVR",
            "Usuário do NVR (deixe em branco para tentar sem senha):",
            parent=self,
        )
        if usuario is None:
            return
        senha = simpledialog.askstring(
            "Conectar ao NVR",
            "Senha do NVR (a mesma usada no app/gravador):",
            show="*",
            parent=self,
        )
        if senha is None:
            return
        self.busca_em_andamento = True
        self._resultado_nvr = None
        self.botao_buscar.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.botao_nvr.configure(state="disabled")
        self.status_busca.set(f"Conectando ao NVR {endereco} (ONVIF) ...")
        threading.Thread(
            target=self._executar_conexao_nvr,
            args=(endereco, usuario.strip(), senha),
            daemon=True,
        ).start()
        self.after(500, self._aguardar_conexao_nvr)

    def _executar_conexao_nvr(self, endereco, usuario, senha):
        try:
            self._resultado_nvr = listar_canais_nvr(endereco, usuario, senha)
        except Exception as exc:  # NVR pode devolver XML/HTTP fora do padrão.
            self._resultado_nvr = ([], f"falha: {exc}")

    def _aguardar_conexao_nvr(self):
        if self._resultado_nvr is None:
            self.after(500, self._aguardar_conexao_nvr)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        self.botao_auto.configure(state="normal")
        self.botao_nvr.configure(state="normal")
        canais, erro = self._resultado_nvr
        self._resultado_nvr = None
        if isinstance(canais, str):
            canais, erro = [], canais
        if not canais:
            self.status_busca.set(
                f"Falha ao conectar ao NVR: {(erro or 'canais não encontrados').removeprefix('falha: ')}"
            )
            return
        endereco = self.entrada_nvr.get().strip()
        rotulos = []
        self._canais_nvr = {}
        for indice, canal in enumerate(canais, start=1):
            nome = (canal["nome"] or "").strip()
            base_rotulo = f"Canal {indice}: {nome}" if nome else f"Canal {indice}"
            rotulo, marca = base_rotulo, ""
            while rotulo in self._canais_nvr:
                marca += "·"
                rotulo = f"{base_rotulo} {marca}"
            self._canais_nvr[rotulo] = canal["url"]
            rotulos.append(rotulo)
        self.combo_ip.configure(values=rotulos)
        self.combo_ip.set(rotulos[0])
        self.status_busca.set(
            f"NVR {endereco}: {len(rotulos)} canal(is) encontrado(s). "
            "Escolha o canal em “Câmera” e clique em Adicionar câmera de rede."
        )

    def buscar_por_id_cms(self):
        """Procura a câmera pelo ID/UID cadastrado no software CMS."""
        if self.busca_em_andamento:
            return
        texto = self.entrada_id.get().strip()
        if not texto:
            self.status_busca.set(
                "Informe o ID/UID da câmera no CMS (o número da etiqueta) "
                "e clique em Buscar pelo ID do CMS."
            )
            return
        ip_local = obter_ip_local()
        if ip_local is None:
            self.status_busca.set(
                "Não foi possível identificar a rede local (Wi-Fi/LAN)."
            )
            return
        self.busca_em_andamento = True
        self._resultado_cms = None
        self.botao_buscar.configure(state="disabled")
        self.botao_auto.configure(state="disabled")
        self.botao_nvr.configure(state="disabled")
        self.botao_cms.configure(state="disabled")
        self.status_busca.set(
            f"Procurando o ID/UID {texto} nas portas de CMS da rede local ..."
        )
        threading.Thread(
            target=self._executar_busca_cms,
            args=(texto, ip_local),
            daemon=True,
        ).start()
        self.after(500, self._aguardar_busca_cms)

    def _executar_busca_cms(self, texto, ip_local):
        try:
            self._resultado_cms = localizar_camera_cms(texto, ip_local)
        except OSError as exc:
            self._resultado_cms = ([], f"falha: {exc}")

    def _aguardar_busca_cms(self):
        if self._resultado_cms is None:
            self.after(500, self._aguardar_busca_cms)
            return
        self.busca_em_andamento = False
        self.botao_buscar.configure(state="normal")
        self.botao_auto.configure(state="normal")
        self.botao_nvr.configure(state="normal")
        self.botao_cms.configure(state="normal")
        candidatos, erro = self._resultado_cms
        self._resultado_cms = None
        if isinstance(candidatos, str):
            candidatos, erro = [], candidatos
        if not candidatos:
            self.status_busca.set(erro or "Nenhum aparelho com esse ID/UID na rede local.")
            return
        rotulos = []
        sem_rtsp = []
        for candidato in candidatos:
            ip = candidato["ip"]
            if candidato.get("confere"):
                rotulo = f"{ip} (ID confere)"
            elif candidato.get("cms"):
                rotulo = f"{ip} (porta CMS aberta)"
            elif candidato["onvif"]:
                rotulo = f"{ip} (ONVIF)"
            elif candidato["portas"]:
                rotulo = f"{ip}:{candidato['portas'][0]}"
            else:
                rotulo = ip
            while rotulo in self._canais_nvr:
                rotulo += "·"
            rotulos.append(rotulo)
            url = candidato.get("url")
            if not url:
                porta_rtsp = next(
                    (p for p in candidato["portas"] if p in PORTAS_RTSP), None
                )
                if porta_rtsp:
                    url = (
                        f"rtsp://{ip}" if porta_rtsp == 554 else f"rtsp://{ip}:{porta_rtsp}"
                    )
            if url:
                self._canais_nvr[rotulo] = url
            else:
                sem_rtsp.append(ip)
        self.combo_ip.configure(values=rotulos)
        self.combo_ip.set(rotulos[0])
        partes = [f"{len(rotulos)} aparelho(s) encontrado(s) na rede local."]
        confirmados = sum(1 for c in candidatos if c.get("confere"))
        if confirmados:
            partes.append(
                f"O ID/UID confere com o serial de {confirmados} deles."
            )
        if sem_rtsp:
            partes.append(
                "Sem porta RTSP aberta em: "
                + ", ".join(sem_rtsp[:4])
                + ("..." if len(sem_rtsp) > 4 else "")
                + ". Use Configurar automaticamente (ONVIF) nesses casos."
            )
        partes.append(
            "Escolha o aparelho em “Câmera” e clique em Adicionar câmera de rede."
        )
        self.status_busca.set(" ".join(partes))

    def _url_da_camera_rede(self, texto):
        """Monta a URL RTSP a partir do texto do campo 'Câmera'."""
        url_nvr = self._canais_nvr.get(texto)
        if url_nvr:
            return url_nvr
        if "://" in texto:
            return texto.strip()
        ip_porta = texto.split(" ")[0]
        ip, separador, porta = ip_porta.partition(":")
        porta_rtsp = int(porta) if separador and porta.isdigit() else 554
        caminho = self.entrada_caminho.get().strip() or "/stream1"
        if not caminho.startswith("/"):
            caminho = "/" + caminho
        return f"rtsp://{ip}:{porta_rtsp}{caminho}"

    def copiar_url_camera(self):
        """Copia a URL RTSP da câmera escolhida (para usar em outro player)."""
        texto = self.combo_ip.get().strip()
        if not texto:
            messagebox.showerror(
                "Copiar URL RTSP",
                "Escolha ou digite a câmera no campo 'Câmera' antes de copiar.",
                parent=self,
            )
            return
        url = self._url_da_camera_rede(texto)
        copiar_texto(self, url)
        self.mensagem.set(f"URL copiada: {url}")

    def colar_url_camera(self):
        """Cola uma URL RTSP (com usuário e senha) e adiciona a câmera."""
        texto = obter_texto_colado(self).strip()
        if not texto:
            self.mensagem.set("A área de transferência está vazia.")
            return
        if "://" not in texto:
            self.combo_ip.set(texto)
            self.mensagem.set(
                "Texto colado no campo 'Câmera'. Confira o caminho RTSP e clique "
                "em 'Adicionar câmera de rede'."
            )
            return
        self.combo_ip.set(texto)
        self.adicionar_camera_rede()

    def adicionar_camera_rede(self):
        texto = self.combo_ip.get().strip()
        if not texto:
            messagebox.showerror(
                "Câmera de rede", "Busque ou digite o IP da câmera.", parent=self
            )
            return
        url_nvr = self._canais_nvr.get(texto)
        if url_nvr:
            try:
                host = urlsplit(url_nvr).hostname or ""
            except ValueError:
                host = ""
            rotulo = texto if (not host or host in texto) else f"{texto} ({host})"
            self._adicionar_camera_interna(url_nvr, rotulo)
            return
        url = self._url_da_camera_rede(texto)
        try:
            rotulo = urlsplit(url).hostname or texto
        except ValueError:
            rotulo = texto
        self._adicionar_camera_interna(url, rotulo)

    def _adicionar_camera_interna(self, origem, rotulo):
        if any(camera.origem == origem for camera in self.cameras.values()):
            self.mensagem.set(f"A câmera {rotulo} já está adicionada.")
            return
        id_camera = self._proximo_id
        self._proximo_id += 1
        camera = Camera(id_camera, origem, rotulo)
        self.cameras[id_camera] = camera
        painel = ttk.LabelFrame(self.grade, text=f"Câmera {rotulo}", padding=6)
        imagem = ttk.Label(painel, text="Conectando...", anchor="center")
        imagem.pack(fill="both", expand=True)
        botoes = ttk.Frame(painel)
        botoes.pack(fill="x", pady=(6, 0))
        gravar = ttk.Button(
            botoes, text="Iniciar gravação",
            command=lambda c=camera: self.alternar_gravacao(c),
        )
        gravar.pack(side="left")
        ttk.Button(botoes, text="Tirar foto", command=lambda c=camera: self.tirar_foto(c)).pack(
            side="left", padx=5
        )
        ttk.Button(
            botoes, text="Remover", command=lambda i=id_camera: self.remover_camera(i)
        ).pack(side="right")
        self.paineis[id_camera] = {
            "painel": painel, "imagem": imagem, "gravar": gravar, "foto": None
        }
        self._organizar_grade()
        self.mensagem.set(f"Câmera {rotulo} adicionada.")

    def adicionar_por_qr(self):
        """Lê um QR code (arquivo ou câmera) para localizar/configurar a câmera."""
        caminho = filedialog.askopenfilename(
            parent=self,
            title="Selecionar imagem com QR da câmera",
            filetypes=[
                ("Imagens", "*.png *.jpg *.jpeg *.bmp *.webp *.pnm"),
                ("Todos os arquivos", "*.*"),
            ],
        )
        if not caminho:
            return
        texto = ler_qr_arquivo(caminho)
        if not texto:
            messagebox.showerror(
                "QR não lido",
                "Não consegui decodificar um QR code nesta imagem.",
                parent=self,
            )
            return
        self.aplicar_dados_qr(texto)

    def aplicar_dados_qr(self, texto):
        texto = texto.strip()
        if not texto:
            return
        texto_limpo = texto
        for prefixo in (
            "YCC365-",
            "YOSEEE:",
            "Yoosee:",
            "IPC-",
            "XM-",
            "XMEYE:",
        ):
            if texto_limpo.upper().startswith(prefixo.upper()):
                texto_limpo = texto_limpo[len(prefixo):].strip()
        self.entrada_id.delete(0, "end")
        self.entrada_id.insert(0, texto_limpo)
        if "://" in texto_limpo:
            self.localizar_camera_rede()
            return
        if texto_limpo.startswith("{"):
            try:
                dados = json.loads(texto_limpo)
                for chave in (
                    "rtsp",
                    "url",
                    "stream",
                    "uri",
                    "rtspUrl",
                    "address",
                    "playUrl",
                ):
                    if dados.get(chave):
                        self.entrada_id.delete(0, "end")
                        self.entrada_id.insert(0, str(dados[chave]))
                        self.localizar_camera_rede()
                        return
                sn = (
                    dados.get("sn")
                    or dados.get("serial")
                    or dados.get("deviceSn")
                    or dados.get("devSn")
                    or dados.get("uid")
                    or dados.get("deviceId")
                    or dados.get("id")
                    or dados.get("s/n")
                )
                if sn:
                    self.entrada_id.delete(0, "end")
                    self.entrada_id.insert(0, str(sn).strip())
                    self.localizar_camera_rede()
                    return
                for chave in ("ip", "host", "deviceIp", "ipaddr"):
                    if dados.get(chave):
                        caminho = (
                            dados.get("path")
                            or dados.get("rtspPath")
                            or dados.get("streamPath")
                            or "/stream1"
                        )
                        porta = dados.get("port") or 554
                        usuario = dados.get("user") or dados.get("username") or dados.get("account")
                        senha = dados.get("pass") or dados.get("password") or dados.get("pwd")
                        if usuario and senha:
                            url = (
                                f"rtsp://{urllib.parse.quote(str(usuario))}:"
                                f"{urllib.parse.quote(str(senha))}@{dados[chave]}:"
                                f"{porta}{caminho if str(caminho).startswith('/') else '/' + str(caminho)}"
                            )
                        else:
                            url = f"rtsp://{dados[chave]}:{porta}{caminho if str(caminho).startswith('/') else '/' + str(caminho)}"
                        self.entrada_id.delete(0, "end")
                        self.entrada_id.insert(0, url)
                        self.localizar_camera_rede()
                        return
            except (json.JSONDecodeError, ValueError):
                pass
        self.localizar_camera_rede()


    def mostrar_redes_wifi(self):
        self.status_busca.set("Procurando redes Wi-Fi próximas...")
        self.update_idletasks()
        redes = detectar_redes_wifi()
        if not redes:
            self.status_busca.set(
                "Nenhuma rede Wi-Fi detectada. Verifique permissões (nmcli/iwlist) ou use o botão Gerar QR."
            )
            return
        janela = tk.Toplevel(self)
        janela.title("Redes Wi-Fi detectadas")
        janela.geometry("420x320")
        janela.transient(self)
        colunas = ("ssid", "sinal", "seguranca", "status")
        arvore = ttk.Treeview(janela, columns=colunas, show="headings", height=12)
        arvore.heading("ssid", text="SSID")
        arvore.heading("sinal", text="Sinal")
        arvore.heading("seguranca", text="Segurança")
        arvore.heading("status", text="Status")
        arvore.column("ssid", width=200)
        arvore.column("sinal", width=60)
        arvore.column("seguranca", width=100)
        arvore.column("status", width=80)
        for r in redes:
            arvore.insert(
                "",
                "end",
                values=(r["ssid"], r["sinal"], r["seguranca"], "Conectado" if r["conectado"] else "-"),
            )
        arvore.pack(fill="both", expand=True, padx=8, pady=8)
        info = obter_wifi_info()
        atual = info.get("ssid") or ""
        self.status_busca.set(
            f"{len(redes)} rede(s) Wi-Fi detectadas. Conectado em: {atual or 'desconhecido'}"
        )
        ttk.Button(janela, text="Fechar", command=janela.destroy).pack(pady=4)

    def gerar_qr_config_wifi(self):
        """Gera QR para conectar câmera Yoosee/XMEYE/etc na Wi-Fi atual."""
        if qrcode is None:
            messagebox.showerror(
                "qrcode não instalado",
                "O módulo 'qrcode' não está disponível.",
                parent=self,
            )
            return
        info = obter_wifi_info()
        ssid = info.get("ssid")
        if not ssid:
            ssid = simpledialog.askstring(
                "SSID Wi-Fi",
                "Nome da rede Wi-Fi (SSID):",
                parent=self,
            )
            if not ssid:
                return
        senha = simpledialog.askstring(
            "Senha Wi-Fi",
            "Senha da rede Wi-Fi (deixe em branco se aberta):",
            show="*",
            parent=self,
        )
        if senha is None:
            return
        tipo = simpledialog.askstring(
            "Tipo de segurança",
            "Tipo: WPA, WEP ou nopass (padrão WPA):",
            initialvalue="WPA",
            parent=self,
        )
        if tipo is None:
            tipo = "WPA"
        tipo = tipo.strip().upper()

        def esc(s):
            for c in ("\\", ";", ",", ":", '"'):
                s = str(s).replace(c, "\\" + c)
            return s

        if tipo == "NOPASS":
            conteudo = "WIFI:T:nopass;S:" + esc(ssid) + ";;"
        else:
            conteudo = (
                "WIFI:T:" + tipo + ";S:" + esc(ssid) + ";P:" + esc(senha) + ";H:false;;"
            )

        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(conteudo)
        qr.make(fit=True)
        imagem = qr.make_image(fill_color="black", back_color="white")
        janela = tk.Toplevel(self)
        janela.title("QR para configuração Wi-Fi da câmera")
        janela.geometry("320x380")
        janela.transient(self)
        janela.resizable(False, False)
        ttk.Label(janela, text=f"Rede: {ssid}\nAponte este QR com o app da câmera Yoosee/XMEYE").pack(pady=8)
        try:
            from PIL import ImageTk
            img_tk = ImageTk.PhotoImage(imagem.convert("RGB"))
            lbl = ttk.Label(janela, image=img_tk)
            lbl.image = img_tk
            lbl.pack()
        except Exception:
            ttk.Label(janela, text=conteudo).pack(padx=10)
        ttk.Label(
            janela,
            text=(
                "Muitos modelos Yoosee pedem esse QR no modo 'Configuração por rede Wi-Fi'\n"
                "ou 'Smart Config'. Se não funcionar, use o modo AP da câmera."
            ),
            wraplength=300,
            justify="center",
        ).pack(pady=6)
        ttk.Button(janela, text="Fechar", command=janela.destroy).pack(pady=4)
        self.status_busca.set(f"QR Wi-Fi gerado para {ssid}")

    def gerar_qr_app(self):
        """Gera um QR com a URL/credenciais do app para uso em outros lugares."""
        link = self.link_web.get()
        if not link.startswith("https://"):
            self.status_busca.set("O link HTTPS ainda não está disponível.")
            return
        if qrcode is None:
            messagebox.showerror(
                "qrcode não instalado",
                "O módulo 'qrcode' não está disponível.",
                parent=self,
            )
            return
        conteudo = json.dumps(
            {"type": "monitoramento-cameras", "url": link, "user": USUARIO_WEB},
            ensure_ascii=False,
        )
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(conteudo)
        qr.make(fit=True)
        imagem = qr.make_image(fill_color="black", back_color="white")
        arquivo = filedialog.asksaveasfilename(
            parent=self,
            title="Salvar QR do app",
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg"), ("Todos", "*.*")],
            initialfile="monitoramento-cameras-app.png",
        )
        if not arquivo:
            return
        try:
            imagem.save(arquivo)
            self.status_busca.set(f"QR do app salvo: {arquivo}")
            try:
                webbrowser.open(arquivo)
            except OSError:
                pass
        except OSError as exc:
            messagebox.showerror("Erro ao salvar QR", str(exc), parent=self)

    def _organizar_grade(self):
        for posicao, dados in enumerate(self.paineis.values()):
            dados["painel"].grid(row=posicao // 2, column=posicao % 2, sticky="nsew", padx=5, pady=5)
        for coluna in range(2):
            self.grade.columnconfigure(coluna, weight=1)
        for linha in range((len(self.paineis) + 1) // 2):
            self.grade.rowconfigure(linha, weight=1)

    def alternar_gravacao(self, camera):
        dados = self.paineis[camera.id]
        if camera.gravando.is_set():
            camera.gravando.clear()
            dados["gravar"].configure(text="Iniciar gravação")
            self.mensagem.set(f"Gravação da câmera {camera.rotulo} encerrada.")
        else:
            camera.gravando.set()
            dados["gravar"].configure(text="Parar gravação")
            self.mensagem.set(f"Gravando câmera {camera.rotulo}...")

    def tirar_foto(self, camera):
        frame = camera.obter_frame()
        if frame is None:
            self.mensagem.set(f"A câmera {camera.rotulo} ainda não está disponível.")
            return
        arquivo = PASTA_CAPTURAS / (
            f"camera_{rotulo_para_arquivo(camera.rotulo)}"
            f"_{datetime.now():%Y%m%d_%H%M%S}.jpg"
        )
        if cv2.imwrite(str(arquivo), frame):
            self.mensagem.set(f"Foto salva: {arquivo}")
        else:
            self.mensagem.set("Não foi possível salvar a foto.")

    def remover_camera(self, indice):
        camera = self.cameras.pop(indice)
        camera.fechar()
        self.paineis.pop(indice)["painel"].destroy()
        self._organizar_grade()
        self.mensagem.set(f"Câmera {camera.rotulo} removida.")

    def mostrar_janela_varredura(self, lista):
        janela = tk.Toplevel(self)
        janela.title("Varredura completa da rede - Câmeras encontradas")
        janela.geometry("1100x650")
        janela.transient(self)

        topo = ttk.Frame(janela, padding=8)
        topo.pack(fill="x")
        ttk.Label(topo, text=f"Encontrados: {len(lista)} dispositivo(s)").pack(side="left")
        ttk.Label(topo, text="Selecione um item e clique em 'Adicionar ao app'").pack(side="left", padx=12)

        frame = ttk.Frame(janela, padding=8)
        frame.pack(fill="both", expand=True)

        colunas = ("ip", "mac", "portas", "origem", "fabricante", "modelo", "serial", "onvif", "http")
        arvore = ttk.Treeview(frame, columns=colunas, show="headings", height=16)
        arvore.heading("ip", text="IP")
        arvore.heading("mac", text="MAC")
        arvore.heading("portas", text="Portas abertas")
        arvore.heading("origem", text="Origem")
        arvore.heading("fabricante", text="Fabricante")
        arvore.heading("modelo", text="Modelo")
        arvore.heading("serial", text="Serial")
        arvore.heading("onvif", text="ONVIF")
        arvore.heading("http", text="HTTP")

        arvore.column("ip", width=120)
        arvore.column("mac", width=140)
        arvore.column("portas", width=160)
        arvore.column("origem", width=90)
        arvore.column("fabricante", width=120)
        arvore.column("modelo", width=120)
        arvore.column("serial", width=140)
        arvore.column("onvif", width=70)
        arvore.column("http", width=70)

        itens = {}
        for info in lista:
            iid = arvore.insert(
                "",
                "end",
                values=(
                    info.get("ip"),
                    info.get("mac") or "-",
                    ", ".join(str(p) for p in info.get("portas_abertas", [])) or "-",
                    ",".join(info.get("origem", [])) or "-",
                    info.get("fabricante") or "-",
                    info.get("modelo") or "-",
                    info.get("serial") or "-",
                    "Sim" if info.get("onvif") else "Não",
                    str(info.get("http_porta")) if info.get("http_porta") else "-",
                ),
            )
            itens[iid] = info

        scroll = ttk.Scrollbar(frame, orient="vertical", command=arvore.yview)
        arvore.configure(yscrollcommand=scroll.set)
        arvore.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        detalhe = ttk.LabelFrame(janela, text="Detalhes / Canais RTSP encontrados", padding=8)
        detalhe.pack(fill="x", padx=8, pady=(0, 8))
        texto = tk.Text(detalhe, height=9, wrap="word")
        texto.pack(fill="x")

        def ao_selecionar(event=None):
            sel = arvore.selection()
            if not sel:
                return
            info = itens.get(sel[0])
            if not info:
                return
            linhas = []
            linhas.append(f"IP: {info['ip']} | MAC: {info.get('mac') or '-'} | HTTP: {info.get('http_porta') or '-'}")
            linhas.append(f"Portas: {', '.join(str(p) for p in info.get('portas_abertas', []))}")
            linhas.append(f"ONVIF: {'Sim' if info.get('onvif') else 'Não'} | URLs ONVIF: {', '.join(info.get('urls_onvif', [])) or '-'}")
            linhas.append(f"Fabricante: {info.get('fabricante') or '-'} | Modelo: {info.get('modelo') or '-'} | Serial: {info.get('serial') or '-'} | Firmware: {info.get('firmware') or '-'}")
            linhas.append(f"Nome ONVIF: {info.get('nome_onvif') or '-'}")
            if info.get("canais"):
                linhas.append("\nCanais via ONVIF:")
                for c in info["canais"]:
                    linhas.append(f"  - {c.get('nome')}: {c.get('url')}")
            if info.get("rtsp_encontrados"):
                linhas.append("\nRTSP detectado por caminhos:")
                for u in info["rtsp_encontrados"]:
                    linhas.append(f"  - {u}")
            if info.get("perfis"):
                linhas.append(f"\nPerfis ONVIF: {len(info['perfis'])}")
            texto.delete("1.0", "end")
            texto.insert("1.0", "\n".join(linhas))

        arvore.bind("<<TreeviewSelect>>", ao_selecionar)

        botoes = ttk.Frame(janela, padding=8)
        botoes.pack(fill="x")
        def adicionar_selecionado():
            sel = arvore.selection()
            if not sel:
                messagebox.showinfo("Selecionar", "Selecione uma câmera da lista.", parent=janela)
                return
            info = itens.get(sel[0])
            if not info:
                return
            url_add = None
            if info.get("canais"):
                url_add = info["canais"][0]["url"]
            elif info.get("rtsp_encontrados"):
                url_add = info["rtsp_encontrados"][0]
            else:
                ip = info["ip"]
                url_add = testar_caminhos_rtsp(ip, 554) or f"rtsp://{ip}:554/stream1"
            rotulo = info.get("nome_onvif") or info.get("modelo") or info.get("ip")
            self._adicionar_camera_interna(url_add, f"{rotulo} ({info['ip']})")
            self.status_busca.set(f"Adicionado: {rotulo} ({info['ip']})")
            janela.destroy()

        ttk.Button(botoes, text="Adicionar ao app", command=adicionar_selecionado).pack(side="left")
        ttk.Button(botoes, text="Fechar", command=janela.destroy).pack(side="right")

    def atualizar_imagens(self):
        for indice, camera in list(self.cameras.items()):
            frame = camera.obter_frame()
            dados = self.paineis.get(indice)
            if dados is None:
                continue
            if frame is None:
                erro = camera.obter_erro()
                if erro is not None:
                    dados["imagem"].configure(text=erro, image="")
                elif not camera.thread.is_alive():
                    dados["imagem"].configure(text="Câmera indisponível", image="")
                continue
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            imagem = Image.fromarray(frame)
            imagem.thumbnail((max(220, dados["imagem"].winfo_width()),
                              max(150, dados["imagem"].winfo_height())))
            foto = ImageTk.PhotoImage(imagem)
            dados["imagem"].configure(image=foto, text="")
            dados["foto"] = foto  # Mantém a referência para o Tkinter.
        self.after(40, self.atualizar_imagens)

    def fechar(self):
        self._parar_servidor_web()
        for camera in self.cameras.values():
            camera.fechar()
        self.destroy()


if __name__ == "__main__":
    Aplicativo().mainloop()