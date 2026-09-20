# -*- coding: utf-8 -*-
"""
emulador_mock_dofun.py
Simulador de dispositivo Android infectado para testes em bancada.

Substitui as chamadas ADB por respostas simuladas, permitindo validar
a lógica de detecção, pontuação e mitigação do Sentinela Veicular
sem hardware físico.

Uso:
    python emulador_mock_dofun.py                    # Simula dispositivo infectado
    python emulador_mock_dofun.py --cenario limpo    # Simula dispositivo limpo
    python emulador_mock_dofun.py --cenario critico  # Simula infecção crítica
    python emulador_mock_dofun.py --cenario suspeito # Simula infecção parcial
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

# Importa o motor principal
import sentinela_veicular as sv


# ---------------------------------------------------------------------------
# Cenários de Simulação
# ---------------------------------------------------------------------------

CENARIOS = {
    "limpo": {
        "descricao": "Multimídia genérica sem nenhum malware instalado",
        "brand": "GenericBrand",
        "model": "HU-9100 Clean",
        "packages": [
            "package:com.spotify.music installer=com.android.vending",
            "package:com.waze installer=com.android.vending",
            "package:com.whatsapp installer=com.android.vending",
        ],
        "deposito": {
            path: "ls: {}: No such file or directory"
            for path in sv.FALLBACK_IOCS["caminhos_deposito"]
        },
        "netstat": (
            "Proto Recv-Q Send-Q Local Address    Foreign Address  State\n"
            "tcp        0      0 192.168.1.50:443 142.250.79.3:443 ESTABLISHED\n"
        ),
        "dumpsys_services": (
            "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
            "  * ServiceRecord{abc123 com.spotify.music/.MediaService}\n"
            "  * ServiceRecord{def456 com.waze/.WazeService}\n"
        ),
    },
    "suspeito": {
        "descricao": "Multimídia com TWCore presente mas sem payload ativo",
        "brand": "DoFun",
        "model": "DF-7862 Pro",
        "packages": [
            "package:com.tw.core installer=null",
            "package:com.spotify.music installer=com.android.vending",
            "package:com.waze installer=com.tw.core",
        ],
        "deposito": {
            sv.FALLBACK_IOCS["caminhos_deposito"][0]: (
                "total 2048\n"
                "-rw-r--r-- 1 root root 1048576 Sep 15 10:30 update_v2.apk\n"
            ),
        },
        "netstat": (
            "Proto Recv-Q Send-Q Local Address    Foreign Address  State\n"
            "tcp        0      0 192.168.1.50:443 142.250.79.3:443 ESTABLISHED\n"
        ),
        "dumpsys_services": (
            "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
            "  * ServiceRecord{abc123 com.tw.core/.TWCoreService}\n"
            "  * ServiceRecord{ghi789 com.spotify.music/.MediaService}\n"
        ),
    },
    "critico": {
        "descricao": "Multimídia totalmente comprometida com JarService ativo e conexão C2",
        "brand": "TWCore",
        "model": "TW-9863 Max",
        "packages": [
            "package:com.tw.core installer=null",
            "package:com.tw.core.service installer=com.tw.core",
            "package:com.jar.service installer=com.tw.core",
            "package:com.moyu.service installer=com.tw.core",
            "package:com.spotify.music installer=com.tw.core",
            "package:com.cleanmaster.fake installer=com.tw.core",
            "package:com.waze installer=com.android.vending",
        ],
        "deposito": {
            sv.FALLBACK_IOCS["caminhos_deposito"][0]: (
                "total 8192\n"
                "-rw-r--r-- 1 root root 2097152 Sep 18 03:15 jarservice_v3.apk\n"
                "-rw-r--r-- 1 root root 1048576 Sep 18 03:15 moyu_payload.apk\n"
                "-rw-r--r-- 1 root root 524288  Sep 17 22:40 adfraud_module.apk\n"
            ),
            sv.FALLBACK_IOCS["caminhos_deposito"][2]: (
                "total 4096\n"
                "-rw-r--r-- 1 root root 3145728 Sep 19 01:22 proxy_socks5.apk\n"
            ),
        },
        "netstat": (
            "Proto Recv-Q Send-Q Local Address           Foreign Address          State\n"
            "tcp        0      0 192.168.1.50:44312       144.217.243.201:8080     ESTABLISHED\n"
            "tcp        0      0 192.168.1.50:55123       198.244.238.165:443      ESTABLISHED\n"
            "tcp        0      0 192.168.1.50:33890       142.250.79.3:443         ESTABLISHED\n"
        ),
        "dumpsys_services": (
            "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
            "  * ServiceRecord{aaa111 com.tw.core/.TWCoreService}\n"
            "  * ServiceRecord{bbb222 com.tw.core.service/.DownloaderService}\n"
            "  * ServiceRecord{ccc333 com.jar.service/.JarService}\n"
            "  * ServiceRecord{ddd444 com.jar.service/.PushService}\n"
            "  * ServiceRecord{eee555 com.moyu.service/.MoYuService}\n"
            "  * ServiceRecord{fff666 com.moyu.service/.SilentInstaller}\n"
            "  * ServiceRecord{ggg777 com.spotify.music/.MediaService}\n"
        ),
    },
}


# ---------------------------------------------------------------------------
# Mock da função executar_adb
# ---------------------------------------------------------------------------
class MockADB:
    """Intercepta chamadas ADB e retorna respostas simuladas."""

    def __init__(self, cenario):
        self.cenario = cenario
        self.log_chamadas = []
        self.mitigacoes = []

    def __call__(self, args, serial=None, timeout=15):
        cmd = " ".join(args)
        self.log_chamadas.append(cmd)

        # getprop (identidade)
        if "getprop" in cmd:
            return 0, f"{self.cenario['brand']}\n{self.cenario['model']}\n", ""

        # pm list packages
        if "pm list packages" in cmd:
            return 0, "\n".join(self.cenario["packages"]) + "\n", ""

        # dumpsys activity services
        if "dumpsys activity services" in cmd:
            return 0, self.cenario.get("dumpsys_services", ""), ""

        # ls (diretórios de depósito)
        if cmd.startswith("shell ls"):
            caminho = args[-1] if len(args) > 2 else ""
            resposta = self.cenario["deposito"].get(
                caminho,
                f"ls: {caminho}: No such file or directory",
            )
            return 0, resposta, ""

        # netstat
        if "netstat" in cmd:
            return 0, self.cenario.get("netstat", ""), ""

        # /proc/net/tcp (fallback)
        if "proc/net/tcp" in cmd:
            return 0, "", ""

        # Comandos de mitigação (force-stop, disable, uninstall, rm)
        if any(k in cmd for k in ("force-stop", "disable-user", "uninstall")):
            pkg = args[-1] if args else "desconhecido"
            self.mitigacoes.append(f"[MOCK] Mitigação executada: {cmd}")
            return 0, f"Package {pkg} disabled\n", ""

        if "rm" in cmd:
            arquivo = args[-1] if args else ""
            self.mitigacoes.append(f"[MOCK] Arquivo removido: {arquivo}")
            return 0, "", ""

        # adb devices
        if "devices" in cmd:
            return 0, "List of devices attached\nMOCK_SERIAL_001\tdevice\n", ""

        return 0, "", ""


# ---------------------------------------------------------------------------
# Execução do Simulador
# ---------------------------------------------------------------------------
def executar_simulacao(nome_cenario, mitigar=False, saida_json=None):
    cenario = CENARIOS.get(nome_cenario)
    if not cenario:
        print(f"Cenário '{nome_cenario}' não encontrado.")
        print(f"Cenários disponíveis: {', '.join(CENARIOS.keys())}")
        sys.exit(1)

    mock = MockADB(cenario)
    iocs = sv.FALLBACK_IOCS

    print("=" * 65)
    print(f"SIMULADOR DE TESTES — SENTINELA VEICULAR")
    print(f"Cenário    : {nome_cenario.upper()}")
    print(f"Descrição  : {cenario['descricao']}")
    print(f"Mitigação  : {'ATIVADA' if mitigar else 'DESATIVADA'}")
    print(f"Data/Hora  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Substitui a função executar_adb pelo mock
    with patch.object(sv, "executar_adb", mock):
        resultado = sv.auditar_dispositivo(
            "MOCK_SERIAL_001", iocs, mitigar=mitigar,
        )

    # Exibe relatório formatado
    print(sv.formatar_relatorio_texto(resultado))

    # Log de chamadas ADB interceptadas
    print(f"\n{'─' * 65}")
    print(f"[DEBUG] Chamadas ADB interceptadas: {len(mock.log_chamadas)}")
    for i, c in enumerate(mock.log_chamadas, 1):
        print(f"  {i:2d}. {c}")

    if mock.mitigacoes:
        print(f"\n[DEBUG] Ações de mitigação simuladas:")
        for m in mock.mitigacoes:
            print(f"  {m}")

    # Saída JSON
    if saida_json:
        Path(saida_json).write_text(
            json.dumps(resultado, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] JSON salvo em: {saida_json}")

    return resultado


def main():
    parser = argparse.ArgumentParser(
        description="Simulador de testes para o Sentinela Veicular.",
    )
    parser.add_argument(
        "--cenario", default="critico",
        choices=list(CENARIOS.keys()),
        help="Cenário de simulação (padrão: critico).",
    )
    parser.add_argument(
        "--mitigar", action="store_true",
        help="Simula execução das ações de mitigação.",
    )
    parser.add_argument(
        "--json-saida",
        help="Salva o resultado da simulação em JSON.",
    )
    parser.add_argument(
        "--todos", action="store_true",
        help="Executa todos os cenários sequencialmente.",
    )
    args = parser.parse_args()

    if args.todos:
        for nome in CENARIOS:
            executar_simulacao(nome, mitigar=args.mitigar)
            print("\n\n")
    else:
        executar_simulacao(
            args.cenario,
            mitigar=args.mitigar,
            saida_json=args.json_saida,
        )


if __name__ == "__main__":
    main()
