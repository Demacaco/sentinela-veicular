# 🛡️ Sentinela Veicular

> Ferramenta de auditoria, diagnóstico e neutralização de malwares pré-instalados (DoFun, TWCore, JarService, BadBox) em centrais multimídia Android.

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Status: Em Desenvolvimento](https://img.shields.io/badge/status-ativo-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

---

## 🚨 O Problema: Malwares Pré-instalados em Carros

Investigações de segurança globais e reportagens na imprensa especializada (como [Canaltech](https://canaltech.com.br/seguranca/virus-no-carro-malware-infecta-central-multimidia-sem-motorista-perceber/) e [VirtuaWorks](https://virtuaworks.com.br/ciberseguranca-em-carros-conectados/)) revelaram que milhões de centrais multimídia Android no mercado pós-venda (*aftermarket*) já **saem de fábrica com backdoors integrados na partição de sistema (ROM)**.

### Sintomas no Veículo:
- 📱 **Consumo invisível de internet:** Franquia do chip 4G ou do roteador Wi-Fi do carro acaba rapidamente sem uso real.
- 🔥 **Superaquecimento e lentidão:** O processador da multimídia fica em 100% de uso executando tarefas de botnet em segundo plano.
- 🔋 **Drenagem da bateria do carro:** O malware impede que a central entre em modo de repouso profundo (*deep sleep*) com a chave desligada.
- 🔓 **Risco de privacidade:** Acesso indevido a contatos telefônicos, GPS e tráfego de dados.

---

## 🎯 O que é o Sentinela Veicular?

O **Sentinela Veicular** é uma solução leve e automatizada que se conecta à central multimídia via interface de depuração USB (ADB) para:
1. **Identificar firmwares comprometidos** (linhas DoFun, TWCore, BadBox, MoYu).
2. **Neutralizar serviços maliciosos ativos** (`pm disable-user`) sem exigir procedimentos arriscados de *flash* de ROM.
3. **Limpar arquivos residuais** nos diretórios de despejo de APKs não autorizados.
4. **Gerar um Laudo Técnico de Segurança** atestando a integridade da central.

---

## 🚀 Como Executar

### Pré-requisitos
- Python 3.8 ou superior instalado.
- Android Platform Tools (`adb`) acessível no PATH do sistema.
- Ativar a **Depuração USB** na multimídia (toque 7 vezes em *Número da Versão* nas configurações da central).

### Execução Básica
```bash
# Clone o repositório
git clone https://github.com/Demacaco/sentinela-veicular.git
cd sentinela-veicular

# Instale as dependências (opcionais para saída colorida)
pip install -r requirements.txt

# Executa a verificação padrão
python sentinela_veicular.py

# Executa com neutralização automática das ameaças e geração de relatório
python sentinela_veicular.py --mitigar --saida laudo_multimidia.txt

# Modo Sentinela (Monitoramento contínuo em bancada/oficina)
python sentinela_veicular.py --monitor --intervalo 120
