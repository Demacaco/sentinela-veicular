# -*- coding: utf-8 -*-
"""
sentinela_veicular.py  v1.1
Sistema de Detecção e Prevenção de Ameaças Veiculares Android
(JarService / DoFun / BadBox)

Novidades v1.1:
  - IOCs externalizados em iocs.json (atualização sem redeploy)
  - Detecção de serviços ocultos via dumpsys activity services
  - Saída estruturada em JSON (--json / --json-saida)
  - Tratamento robusto de erros no rm de APKs residuais

Uso:
    python sentinela_veicular.py
    python sentinela_veicular.py --mitigar --saida relatorio.txt
    python sentinela_veicular.py --json --json-saida auditoria.json
    python sentinela_veicular.py --monitor --intervalo 120
    python sentinela_veicular.py --iocs caminho/para/iocs_custom.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Carregamento de IOCs (JSON Externo ou Fallback Embutido)
# ---------------------------------------------------------------------------
FALLBACK_IOCS = {
    "dominios_c2": [
        "cardoor.cn", "admin.uipoxy.com", "uipoxy.com",
        "dofun.com", "twcore.net",
    ],
    "ips_c2": ["144.217.243.201", "198.244.238.165"],
    "pacotes_maliciosos": [
        "com.tw.core", "com.tw.core.service",
        "com.jar.service", "com.moyu.service",
    ],
    "servicos_suspeitos": [
        "JarService", "PushService", "DownloaderService",
        "TWCoreService", "MoYuService", "SilentInstaller",
    ],
    "caminhos_deposito": [
        "/sdcard/Android/data/com.tw.core/cache/push/apk/",
        "/data/data/com.tw.core/cache/apk/",
        "/sdcard/.dofun_cache/",
    ],
}


def carregar_iocs(caminho_json=None):
    """
    Carrega IOCs de um arquivo JSON externo.
    Se o arquivo não existir ou falhar, usa o fallback embutido.
    """
    # Tenta o caminho fornecido via argumento
    if caminho_json and Path(caminho_json).is_file():
        try:
            dados = json.loads(Path(caminho_json).read_text(encoding="utf-8"))
            log(f"[+] IOCs carregados de: {caminho_json}", Cor.AZUL)
            return dados
        except (json.JSONDecodeError, KeyError) as e:
            log(f"[!] Erro ao ler {caminho_json}: {e}. Usando fallback.", Cor.AMARELO)

    # Tenta o iocs.json ao lado do script
    caminho_padrao = Path(__file__).parent / "iocs.json"
    if caminho_padrao.is_file():
        try:
            dados = json.loads(caminho_padrao.read_text(encoding="utf-8"))
            log(f"[+] IOCs carregados de: {caminho_padrao}", Cor.AZUL)
            return dados
        except (json.JSONDecodeError, KeyError) as e:
            log(f"[!] Erro ao ler {caminho_padrao}: {e}. Usando fallback.", Cor.AMARELO)

    log("[*] Usando base de IOCs embutida (fallback).", Cor.AMARELO)
    return FALLBACK_IOCS


# ---------------------------------------------------------------------------
# Utilitários de Terminal e Cores
# ---------------------------------------------------------------------------
class Cor:
    VERMELHO = "\033[91m"
    AMARELO  = "\033[93m"
    VERDE    = "\033[92m"
    AZUL     = "\033[94m"
    RESET    = "\033[0m"
    NEGRITO  = "\033[1m"

    @staticmethod
    def desativar():
        for k in ("VERMELHO", "AMARELO", "VERDE", "AZUL", "RESET", "NEGRITO"):
            setattr(Cor, k, "")


if sys.platform == "win32":
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass


def log(msg, cor=""):
    print(f"{cor}{msg}{Cor.RESET}" if cor else msg)


def executar_adb(args, serial=None, timeout=15):
    """Executa comando ADB com tratamento seguro de argumentos e timeout."""
    if not shutil.which("adb"):
        raise RuntimeError("ADB não encontrado no PATH do sistema.")

    cmd = ["adb"]
    if serial:
        if not re.match(r"^[\w.:_-]+$", serial):
            raise ValueError(f"Serial ADB inválido: {serial}")
        cmd += ["-s", serial]

    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def obter_dispositivos():
    _, out, _ = executar_adb(["devices"])
    seriais = []
    for linha in out.splitlines()[1:]:
        linha = linha.strip()
        if not linha:
            continue
        partes = linha.split()
        if len(partes) >= 2 and partes[1] == "device":
            seriais.append(partes[0])
    return seriais


# ---------------------------------------------------------------------------
# Decodificadores de Rede (/proc/net/tcp)
# ---------------------------------------------------------------------------
def decodificar_hex_ip(hex_ip):
    """Converte 'C9F3D990' (little-endian hex) em '144.217.243.201'."""
    try:
        ip_bytes = bytes.fromhex(hex_ip)
        return ".".join(str(b) for b in reversed(ip_bytes))
    except Exception:
        return ""


def extrair_ips_proc_net(saida_proc):
    """Extrai IPs remotos únicos a partir de /proc/net/tcp."""
    ips_remotos = set()
    for linha in saida_proc.splitlines():
        partes = linha.strip().split()
        if len(partes) >= 3 and ":" in partes[2]:
            rem_addr = partes[2]
            hex_ip, _ = rem_addr.split(":")
            if len(hex_ip) == 8:
                ip = decodificar_hex_ip(hex_ip)
                if ip and ip != "0.0.0.0":
                    ips_remotos.add(ip)
    return ips_remotos


# ---------------------------------------------------------------------------
# Módulos de Verificação
# ---------------------------------------------------------------------------
def verificar_identidade(serial):
    _, out, _ = executar_adb(
        ["shell", "getprop ro.product.brand; getprop ro.product.model"],
        serial=serial,
    )
    linhas = [l.strip() for l in out.splitlines() if l.strip()]
    return {
        "marca":  linhas[0] if len(linhas) > 0 else "Desconhecida",
        "modelo": linhas[1] if len(linhas) > 1 else "Desconhecido",
    }


def verificar_pacotes(serial, iocs):
    _, out, _ = executar_adb(
        ["shell", "pm", "list", "packages", "-3", "-i"], serial=serial,
    )
    pacotes_mal = set(iocs.get("pacotes_maliciosos", []))
    instalados, suspeitos = [], []

    for linha in out.splitlines():
        linha = linha.strip()
        m = re.match(r"package:(\S+)\s+installer=(\S*)", linha)
        if m:
            pkg, inst = m.group(1), m.group(2)
            instalados.append((pkg, inst))
            if pkg in pacotes_mal or inst in pacotes_mal:
                suspeitos.append((pkg, inst))

    return {"todos": instalados, "suspeitos": suspeitos}


def verificar_servicos_ocultos(serial, iocs):
    """
    [NOVO v1.1] Inspeciona serviços em execução via dumpsys.
    Detecta malware rodando como serviço sem ícone de launcher,
    que o 'pm list packages' não captura adequadamente.
    """
    _, out, _ = executar_adb(
        ["shell", "dumpsys", "activity", "services"], serial=serial, timeout=20,
    )

    nomes_suspeitos = set(iocs.get("servicos_suspeitos", []))
    pacotes_mal = set(iocs.get("pacotes_maliciosos", []))
    encontrados = []

    for linha in out.splitlines():
        linha_lower = linha.strip().lower()
        # Checa nomes de serviço conhecidos
        for nome in nomes_suspeitos:
            if nome.lower() in linha_lower:
                encontrados.append({
                    "tipo": "SERVICO_NOME",
                    "match": nome,
                    "linha": linha.strip()[:120],
                })
        # Checa pacotes maliciosos rodando como serviço
        for pkg in pacotes_mal:
            if pkg.lower() in linha_lower:
                encontrados.append({
                    "tipo": "SERVICO_PACOTE",
                    "match": pkg,
                    "linha": linha.strip()[:120],
                })

    # Deduplica por linha
    vistos = set()
    unicos = []
    for e in encontrados:
        if e["linha"] not in vistos:
            vistos.add(e["linha"])
            unicos.append(e)

    return unicos


def verificar_caminhos_deposito(serial, iocs):
    caminhos = iocs.get("caminhos_deposito", [])
    achados = []
    for caminho in caminhos:
        _, out, _ = executar_adb(["shell", "ls", "-la", caminho], serial=serial)
        if "No such file" not in out and "Permission denied" not in out:
            apks = [
                l.strip().split()[-1]
                for l in out.splitlines()
                if l.strip().endswith(".apk")
            ]
            if apks:
                achados.append({"caminho": caminho, "apks": apks})
    return achados


def verificar_conexoes(serial, iocs):
    dominios = set(iocs.get("dominios_c2", []))
    ips = set(iocs.get("ips_c2", []))
    hits = []

    _, out_netstat, _ = executar_adb(["shell", "netstat", "-tun"], serial=serial)

    if not out_netstat or "Permission denied" in out_netstat or "not found" in out_netstat:
        _, out_proc, _ = executar_adb(
            ["shell", "cat /proc/net/tcp; cat /proc/net/tcp6"], serial=serial,
        )
        ips_ativos = extrair_ips_proc_net(out_proc)
        for ip in ips_ativos:
            if ip in ips:
                hits.append(("IP_REDE_PROC", ip))
    else:
        for dominio in dominios:
            if re.search(rf"\b{re.escape(dominio)}\b", out_netstat):
                hits.append(("DOMINIO_DNS", dominio))
        for ip in ips:
            if re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", out_netstat):
                hits.append(("IP_CONEXAO", ip))

    return hits


# ---------------------------------------------------------------------------
# Ação de Mitigação / Neutralização
# ---------------------------------------------------------------------------
def executar_mitigacao(serial, pacotes_suspeitos, depositos):
    acoes = []

    # 1. Desativa e para pacotes maliciosos
    for pkg, _ in pacotes_suspeitos:
        executar_adb(["shell", "am", "force-stop", pkg], serial=serial)
        c, stdout, stderr = executar_adb(
            ["shell", "pm", "disable-user", pkg], serial=serial,
        )
        if c == 0:
            acoes.append({"acao": "disable", "pacote": pkg, "ok": True})
        else:
            c2, _, _ = executar_adb(
                ["shell", "pm", "uninstall", "-k", "--user", "0", pkg],
                serial=serial,
            )
            acoes.append({
                "acao": "uninstall_fallback",
                "pacote": pkg,
                "ok": c2 == 0,
                "detalhe": stderr.strip() if not c2 == 0 else "",
            })

    # 2. Exclui APKs do diretório de push (com tratamento de erro)
    for dep in depositos:
        caminho = dep["caminho"]
        for apk in dep["apks"]:
            arquivo = f"{caminho}{apk}"
            c, _, stderr = executar_adb(
                ["shell", "rm", "-f", arquivo], serial=serial,
            )
            if c != 0:
                log(f"  [!] Falha ao remover {arquivo}: {stderr.strip()}", Cor.AMARELO)
                acoes.append({
                    "acao": "rm_apk",
                    "arquivo": arquivo,
                    "ok": False,
                    "erro": stderr.strip(),
                })
            else:
                acoes.append({"acao": "rm_apk", "arquivo": arquivo, "ok": True})

    return acoes


# ---------------------------------------------------------------------------
# Relatório e Auditoria
# ---------------------------------------------------------------------------
def auditar_dispositivo(serial, iocs, mitigar=False):
    ident = verificar_identidade(serial)
    pkgs = verificar_pacotes(serial, iocs)
    servicos = verificar_servicos_ocultos(serial, iocs)
    depositos = verificar_caminhos_deposito(serial, iocs)
    hits_rede = verificar_conexoes(serial, iocs)

    # --- Pontuação de risco ---
    pontos = 0
    motivos = []

    if pkgs["suspeitos"]:
        pontos += 5
        motivos.append(f"{len(pkgs['suspeitos'])} pacote(s) malicioso(s) instalado(s).")

    if servicos:
        pontos += 4
        motivos.append(f"{len(servicos)} serviço(s) oculto(s) ativo(s) em segundo plano.")

    if depositos:
        n_apks = sum(len(d["apks"]) for d in depositos)
        pontos += 3
        motivos.append(f"{n_apks} APK(s) residual(is) em diretório(s) de depósito.")

    if hits_rede:
        pontos += 5
        motivos.append(f"{len(hits_rede)} conexão(ões) ativa(s) com IOC(s) de botnet.")

    if pontos >= 5:
        veredito = "CRÍTICO"
    elif pontos >= 3:
        veredito = "SUSPEITO"
    else:
        veredito = "LIMPO"

    # --- Mitigação ---
    acoes_mitigacao = []
    if mitigar and veredito in ("CRÍTICO", "SUSPEITO"):
        acoes_mitigacao = executar_mitigacao(serial, pkgs["suspeitos"], depositos)

    return {
        "versao_sentinela": "1.1.0",
        "timestamp": datetime.now().isoformat(),
        "serial": serial,
        "identidade": ident,
        "pontos": pontos,
        "veredito": veredito,
        "motivos": motivos,
        "pacotes_suspeitos": [
            {"pacote": p, "instalador": i} for p, i in pkgs["suspeitos"]
        ],
        "servicos_ocultos": servicos,
        "depositos": depositos,
        "conexoes_ioc": [
            {"tipo": t, "alvo": a} for t, a in hits_rede
        ],
        "total_apps_terceiros": len(pkgs["todos"]),
        "mitigacao": acoes_mitigacao,
    }


def formatar_relatorio_texto(r):
    """Gera relatório em texto legível para humanos."""
    linhas = [
        "=" * 65,
        "SENTINELA VEICULAR v1.1 — RELATÓRIO DE COMPROMETIMENTO",
        f"Data/Hora : {r['timestamp']}",
        f"Serial ADB: {r['serial']}",
        f"Hardware  : {r['identidade']['marca']} — {r['identidade']['modelo']}",
        f"Veredito  : {r['veredito']} (Score: {r['pontos']})",
        "=" * 65,
    ]

    if r["motivos"]:
        linhas.append("\n[*] MOTIVOS DA CLASSIFICAÇÃO:")
        for m in r["motivos"]:
            linhas.append(f"    → {m}")

    if r["pacotes_suspeitos"]:
        linhas.append("\n[!] PACOTES MALICIOSOS DETECTADOS:")
        for p in r["pacotes_suspeitos"]:
            linhas.append(f"    • {p['pacote']}  (instalador: {p['instalador']})")

    if r["servicos_ocultos"]:
        linhas.append("\n[!] SERVIÇOS OCULTOS EM EXECUÇÃO (dumpsys):")
        for s in r["servicos_ocultos"]:
            linhas.append(f"    • [{s['tipo']}] {s['match']}")
            linhas.append(f"      {s['linha']}")

    if r["depositos"]:
        linhas.append("\n[!] DIRETÓRIOS COM APKs RESIDUAIS:")
        for d in r["depositos"]:
            linhas.append(f"    • {d['caminho']} ({len(d['apks'])} APKs)")
            for a in d["apks"]:
                linhas.append(f"        - {a}")

    if r["conexoes_ioc"]:
        linhas.append("\n[!] CONEXÕES COM IOCs DE BOTNET:")
        for c in r["conexoes_ioc"]:
            linhas.append(f"    • {c['tipo']}: {c['alvo']}")

    if r["mitigacao"]:
        linhas.append("\n[✔] AÇÕES DE MITIGAÇÃO EXECUTADAS:")
        for a in r["mitigacao"]:
            status = "OK" if a.get("ok") else "FALHA"
            detalhe = a.get("erro") or a.get("detalhe") or ""
            desc = a.get("pacote") or a.get("arquivo") or ""
            linhas.append(f"    [{status}] {a['acao']}: {desc} {detalhe}")

    linhas.append(f"\n  Total de apps de terceiros: {r['total_apps_terceiros']}")
    linhas.append("\n" + "=" * 65)
    return "\n".join(linhas)


# ---------------------------------------------------------------------------
# Entrada Principal
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Sentinela Veicular v1.1 — Defesa e Monitoramento Android.",
    )
    parser.add_argument("--serial", help="Serial ADB específico.")
    parser.add_argument("--iocs", help="Caminho para arquivo iocs.json customizado.")
    parser.add_argument("--mitigar", action="store_true",
                        help="Desativa pacotes e remove APKs maliciosos.")
    parser.add_argument("--monitor", action="store_true",
                        help="Executa em loop contínuo de vigilância.")
    parser.add_argument("--intervalo", type=int, default=60,
                        help="Intervalo em segundos no modo monitor (padrão: 60).")
    parser.add_argument("--saida", help="Arquivo para salvar relatório em texto.")
    parser.add_argument("--json", action="store_true",
                        help="Exibe resultado estruturado em JSON no terminal.")
    parser.add_argument("--json-saida",
                        help="Arquivo para salvar resultado em JSON.")
    args = parser.parse_args()

    # Carrega IOCs
    iocs = carregar_iocs(args.iocs)

    # Detecta dispositivos
    dispositivos = [args.serial] if args.serial else obter_dispositivos()
    if not dispositivos:
        log("[-] Nenhum dispositivo ADB detectado. Verifique conexão USB/Wi-Fi.",
            Cor.AMARELO)
        sys.exit(1)

    resultados_json = []

    while True:
        for s in dispositivos:
            try:
                res = auditar_dispositivo(s, iocs, mitigar=args.mitigar)
            except Exception as e:
                log(f"[ERRO] Falha ao auditar {s}: {e}", Cor.VERMELHO)
                resultados_json.append({"serial": s, "erro": str(e)})
                continue

            # Saída visual no terminal
            cor = Cor.VERDE if res["veredito"] == "LIMPO" else Cor.VERMELHO
            log(f"[{res['timestamp']}] {s}: {cor}{res['veredito']}{Cor.RESET}"
                f" (Score: {res['pontos']})")

            # Relatório texto
            if res["veredito"] != "LIMPO" or not args.monitor:
                txt = formatar_relatorio_texto(res)
                if not args.json:
                    print(txt)
                if args.saida:
                    with open(args.saida, "a", encoding="utf-8") as f:
                        f.write(txt + "\n\n")

            # Saída JSON
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))

            resultados_json.append(res)

        # Salva JSON acumulado
        if args.json_saida:
            Path(args.json_saida).write_text(
                json.dumps(resultados_json, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            log(f"[+] JSON salvo em: {args.json_saida}", Cor.AZUL)

        if not args.monitor:
            break
        time.sleep(args.intervalo)


if __name__ == "__main__":
    main()
