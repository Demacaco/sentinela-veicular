# Demacaco Shield

> Monitoramento independente de anomalias em veículos conectados.

O **Demacaco Shield** é um protótipo de segurança automotiva criado para transformar sinais técnicos de veículos modernos em alertas simples para pessoas leigas, oficinas e gestores de frota.

O produto foi pensado para veículos que possuem interfaces como OBD-II, CAN Bus, Bluetooth, telemetria e conectividade com aplicativos. Nesta versão, a aplicação apresenta uma **demonstração de telemetria simulada**. Ela ainda não lê dados reais do veículo.

## O que o aplicativo faz hoje

A versão atual contém três áreas:

- **Visão geral:** mostra o estado de proteção, indicadores de sessão e ações principais.
- **Eventos:** apresenta sinais classificados como ação recomendada, atenção ou resolvido.
- **Ajustes:** permite alternar varredura automática e alertas prioritários.

Cada evento pode ser expandido para mostrar uma explicação em linguagem simples. A interface usa cores e textos para evitar que a pessoa precise entender CAN Bus ou códigos de diagnóstico para compreender o risco.

## Como usar — guia para pessoas leigas

### 1. Abrir o aplicativo

Abra o Demacaco Shield pelo Expo Go usando o QR Code do projeto. Aguarde o carregamento terminar. A tela inicial apresenta o estado atual da sessão.

> O QR Code atual abre uma demonstração dentro do Expo Go. Ele não é um APK instalado e não representa, sozinho, uma conexão com o carro.

### 2. Entender a tela principal

- **Veículo protegido:** significa que não há ameaça crítica na simulação atual.
- **Sinais:** quantidade de categorias observadas na sessão.
- **Latência:** tempo aproximado de resposta do fluxo monitorado.
- **Bloqueios:** ações de proteção simuladas. Na versão atual, o aplicativo não bloqueia comandos reais.

### 3. Ler um evento

Toque em um evento para abrir os detalhes. Use esta regra simples:

- **Ação recomendada:** pare de usar o adaptador, não tente corrigir sozinho e procure uma oficina qualificada.
- **Atenção:** confirme se o adaptador, acessório ou serviço foi autorizado.
- **Resolvido:** o sinal voltou ao comportamento esperado, mas pode continuar registrado no histórico.

### 4. O que fazer diante de um alerta

1. Não interaja com o aplicativo enquanto estiver dirigindo.
2. Estacione em local seguro.
3. Não remova fusíveis, não altere módulos e não envie comandos ao veículo.
4. Verifique se alguém conectou um adaptador OBD-II ou acessório Bluetooth recentemente.
5. Fotografe o alerta e anote data, horário e veículo.
6. Procure uma oficina especializada se o evento for recorrente ou classificado como alto risco.

### 5. Ajustes

Em **Ajustes**, a pessoa pode ativar ou desativar:

- varredura automática;
- alertas prioritários.

Essas opções controlam a experiência da demonstração. Na futura versão com hardware real, elas controlarão o comportamento do monitoramento autorizado.

## Limitações importantes

O protótipo atual usa dados simulados. Ele não oferece garantia de segurança, não detecta invasões reais, não substitui diagnóstico automotivo e não deve ser usado para tomar decisões de condução.

A integração real exigirá um adaptador OBD-II/BLE compatível, um development build próprio e testes em veículos autorizados. O primeiro produto real deve operar em **modo somente leitura**, sem enviar comandos de atuação para ECUs ou sistemas críticos.

## Por que o problema existe

Veículos conectados possuem várias superfícies de exposição: porta de diagnóstico, infotainment, Bluetooth, Wi-Fi, modem celular, aplicativos, serviços remotos e atualizações de software. A NHTSA recomenda uma abordagem em camadas, considerando interfaces com e sem fio como possíveis pontos de entrada e saída de dados.

A ISO/SAE 21434 define requisitos de engenharia para gerenciamento de risco cibernético durante todo o ciclo de vida de sistemas eletrônicos de veículos. A UNECE R155 estabelece uma referência regulatória para cibersegurança veicular e sistemas de gerenciamento de cibersegurança.

## Como o produto pode detectar anomalias

A versão comercial deverá aprender uma linha de base por veículo e comparar novas sessões com o comportamento esperado. Os primeiros detectores recomendados são:

- dispositivo OBD-II ou Bluetooth não reconhecido;
- aumento anormal de frequência de mensagens;
- identificador CAN fora da linha de base;
- sessão diagnóstica em horário ou contexto incomum;
- inconsistência entre velocidade, rotação, ignição e telemetria;
- mudança de comportamento após manutenção ou atualização.

O alerta deve explicar o que aconteceu, por que merece atenção e qual é o próximo passo seguro. O objetivo é apoiar investigação, não assustar o usuário nem prometer proteção absoluta.

## A aplicação vale a pena?

**Sim, como oportunidade de validação — ainda não como produto pronto para escala.**

A tese é mais forte no mercado B2B porque frotas, locadoras, oficinas e seguradoras têm custo financeiro claro quando um veículo fica parado, é adulterado ou sofre uma intervenção não autorizada. Também existe pressão regulatória e de cadeia de fornecedores para tratar riscos cibernéticos durante o ciclo de vida do veículo.

O risco principal é técnico: OBD-II não expõe necessariamente toda a rede CAN, adaptadores baratos podem ser inconsistentes e cada veículo pode ter sinais proprietários. Por isso, a primeira venda deve ser um piloto controlado, não uma promessa de proteção universal.

## Modelo de monetização

### Shield Home

Assinatura por veículo para consumidores, com adaptador certificado, alertas básicos e histórico limitado.

### Shield Pro

Plano para oficinas com múltiplos veículos, relatórios, exportação de evidências e histórico ampliado.

### Shield Fleet

Plano empresarial por veículo monitorado, com painel web, usuários, permissões, alertas e API.

### Serviços profissionais

Receita adicional com instalação, calibração da linha de base, auditoria técnica, integração e relatórios de incidentes.

A recomendação inicial é vender um **piloto pago de 30 a 60 dias**, com cinco a vinte veículos, antes de definir a precificação de escala.

## Mercado e concorrência

O mercado já possui empresas fortes de cibersegurança automotiva. A Upstream oferece uma plataforma cloud para dados de veículos conectados, telemetria, diagnóstico e detecção de anomalias em escala. A VicOne atua com proteção multicamada para OEMs, fornecedores, redes e ciclo de vida do veículo. A PlaxidityX apresenta soluções para o backbone digital de veículos conectados e frotas.

Esses concorrentes normalmente vendem para fabricantes, Tier 1, grandes frotas e centros de operação. A oportunidade do Demacaco Shield não é tentar competir de imediato em toda a cadeia OEM. É começar com um produto simples para oficinas, frotas pequenas e parceiros de instalação, com foco em:

- linguagem acessível;
- hardware independente;
- modo somente leitura;
- alertas explicáveis;
- implantação rápida;
- suporte local e atendimento em português.

Estimativas de mercado publicadas por analistas variam bastante. Elas devem ser usadas apenas como direção, não como prova de receita. A validação decisiva será conseguir pilotos pagos e medir redução de tempo de investigação, eventos úteis detectados e taxa de falsos positivos.

## Plano de entrada no mercado

1. Entrevistar gestores de frota, oficinas e locadoras.
2. Escolher um único adaptador BLE documentado e confiável.
3. Implementar leitura padronizada somente de dados autorizados.
4. Rodar um piloto com cinco a vinte veículos.
5. Medir alertas úteis, falsos positivos e tempo de resposta.
6. Criar um caso de sucesso com números reais.
7. Expandir para assinatura por veículo e painel profissional.

## Roadmap técnico

### Fase atual — demonstração

Dashboard mobile, eventos simulados, severidade explicável e ajustes locais.

### Próxima fase — hardware

Development build, conexão BLE, permissões, descoberta do adaptador e leitura OBD-II padronizada.

### Fase de produto

Linha de base por veículo, histórico persistente, notificações, contas e painel web.

### Fase profissional

Frotas, API, trilha de auditoria, integração com oficinas e avaliação de conformidade.

## Executar o projeto

O projeto usa Expo SDK 58, React Native, TypeScript, Expo Router e NativeWind.

```bash
pnpm install
pnpm check
pnpm test
pnpm dev
```

Para validar Android sem hardware real:

```bash
pnpm exec expo export --platform android --output-dir /tmp/demacaco-export
```

Bluetooth e OBD-II reais não devem ser testados no Expo Go. Eles exigem uma development build própria e um dispositivo físico.

## Fontes

- [NHTSA — Vehicle Cybersecurity](https://www.nhtsa.gov/research/vehicle-cybersecurity)
- [ISO — ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html)
- [UNECE — UN Regulation No. 155](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security)
- [Upstream — Connected Vehicle Cybersecurity](https://upstream.auto/)
- [VicOne — Automotive Cybersecurity](https://vicone.com/)
- [PlaxidityX — Connected Vehicle Security](https://argus-sec.com/)
- [Expo — Development Builds](https://docs.expo.dev/develop/development-builds/introduction/)

## Registro do projeto

A construção, as migrações do Expo SDK e os registros de autorização do usuário estão documentados em [`docs/BUILD_NOTES.md`](docs/BUILD_NOTES.md).

**Status:** protótipo demonstrável; telemetria simulada; não é um produto de segurança certificado.
