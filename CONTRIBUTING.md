# Contribuindo com o Sentinela Veicular 🚗🛡️

Obrigado pelo interesse em ajudar a proteger o ecossistema de centrais multimídia veiculares!

---

## 🛠️ Formas de Contribuir

### 1. 🔌 Testando em Diferentes Aparelhos (Prioridade Máxima!)

O mercado brasileiro possui centenas de marcas e modelos de multimídia Android (Aikon, Winca, Kronos, E-Tech, Eonon, Joying, Teyes, modelos genéricos do AliExpress, etc.).

**Como testar:**
1. Clone o repositório e conecte sua central via USB com Depuração USB ativada.
2. Execute: `python sentinela_veicular.py`
3. Abra uma **Issue** com a tag `[Teste de Hardware]` informando:
   - Marca e modelo da multimídia
   - Versão do Android exibida no sistema
   - Chipset (Allwinner, Rockchip, Unisoc, etc.), se souber
   - Se o script identificou o hardware corretamente
   - Trecho do relatório gerado (oculte informações sensíveis)

### 2. 🔍 Reportando Novos IOCs (Indicadores de Comprometimento)

Se você analisou tráfego de rede, fez engenharia reversa em APKs veiculares ou encontrou novos domínios C2, IPs ou nomes de pacotes suspeitos:

1. Abra uma **Issue** com a tag `[Novo IOC]`
2. Forneça:
   - Tipo do indicador (domínio, IP, hash SHA256, nome de pacote, nome de serviço)
   - Fonte ou método de coleta (PCAP, análise estática, sandbox, etc.)
   - Contexto (em qual modelo de multimídia foi encontrado)
3. Ou envie um **Pull Request** editando diretamente o arquivo `iocs.json`

### 3. 💻 Melhorias no Código

Áreas onde precisamos de ajuda:

- **Interface gráfica (GUI):** Criar uma interface visual simples com Tkinter, CustomTkinter, PySide ou Flutter para uso por leigos
- **Empacotamento:** Criar executável standalone com PyInstaller para Windows (eliminar dependência de Python instalado)
- **Novas verificações ADB:** Inspeção de `logcat`, análise de `dumpsys battery` (wake locks), verificação de `content providers` expostos
- **Android ≤ 7:** Compatibilidade com versões legadas do Android comuns em centrais antigas
- **Testes automatizados:** Ampliar a cobertura do `emulador_mock_dofun.py`

### 4. 📝 Documentação e Tradução

- Tradução do README para inglês (expandir alcance global)
- Guias visuais com capturas de tela: como ativar Depuração USB em cada marca de multimídia
- Tutoriais em vídeo para o canal YouTube de parceiros

---

## 📐 Padrões de Código

- **Linguagem:** Python 3.8+
- **Estilo:** PEP 8 (use `black` ou `ruff` para formatação)
- **Commits:** Em português ou inglês, descritivos (ex: `Adicionar detecção de serviço MoYu via dumpsys`)
- **Docstrings:** Em português, explicando o propósito e os parâmetros

---

## 💼 Parcerias Comerciais

Se você representa uma rede de oficinas, centro automotivo, importadora de multimídias, seguradora de frotas ou canal de mídia automotiva e deseja viabilizar a ferramenta comercialmente:

1. Abra uma **Issue** com o título `[Parceria Comercial]`
2. Ou envie uma mensagem direta pelo perfil do GitHub

Estamos abertos a:
- Pilotos em oficinas e instaladoras
- Distribuição do Kit Pendrive em redes de varejo automotivo
- Certificação de lotes importados de multimídias
- Integração com scanners OBD2 existentes

---

## 📜 Código de Conduta

- Mantenha um ambiente colaborativo, respeitoso e profissional
- Foco no compartilhamento ético de conhecimento em prol da segurança do usuário final
- Divulgação responsável: não publique exploits ou ferramentas ofensivas neste repositório

---

## 🚀 Primeira Contribuição?

1. Faça um **Fork** do repositório
2. Crie uma branch para sua feature: `git checkout -b minha-feature`
3. Faça commit das suas alterações: `git commit -m 'Adicionar nova verificação X'`
4. Envie para o seu fork: `git push origin minha-feature`
5. Abra um **Pull Request** descrevendo o que você fez

Toda contribuição será revisada e creditada. Bem-vindo(a) ao time! 🛡️
