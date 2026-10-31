# Demacaco Shield — Registro de construção

## Registro da solicitação

**Solicitante:** usuário desta sessão.  
**Data da solicitação:** 13 de setembro de 2026.  
**Objetivo:** criar um aplicativo móvel para monitorar comportamento suspeito em veículos modernos com OBD-II, CAN Bus e telemetria.

A solicitação foi interpretada como um protótipo de produto, com foco em clareza de alertas e experiência mobile. O arquivo `DemacacoShield.exe` anexado foi identificado como um executável Windows PE32+ e não foi executado; ele foi tratado somente como referência fornecida pelo solicitante.

## Entrega desta versão

O aplicativo foi implementado sobre o scaffold Expo SDK 54, React Native, TypeScript, Expo Router e NativeWind. A tela principal foi substituída por um dashboard do Demacaco Shield com identidade visual escura, acentos em turquesa e estados de risco legíveis.

A versão atual inclui três áreas navegáveis: **Visão geral**, com status de proteção, indicadores de sessão e ações principais; **Eventos**, com uma lista de sinais simulados classificados em alto, médio e baixo risco e detalhes expansíveis; e **Ajustes**, com controles de varredura automática, alertas prioritários e avisos de segurança.

## Decisões de produto e segurança

O protótipo sinaliza explicitamente que a telemetria é simulada e informa que alertas são indicadores de investigação, não substitutos para diagnóstico automotivo profissional. Nenhum comando é enviado ao veículo, nenhuma ECU é alterada e nenhuma conexão real a OBD-II, CAN Bus ou rede de telemetria foi presumida nesta etapa.

Os dados exibidos são locais e demonstrativos. A integração futura deverá incluir um adaptador veicular compatível, permissões específicas por plataforma, validação de mensagens, isolamento de comandos e uma política clara de atualização segura de firmware. A classificação de risco deverá ser calibrada com dados reais antes de qualquer uso operacional.

## Validação

- TypeScript: `pnpm check` aprovado.
- Testes: `pnpm test` aprovado; três testes do dashboard passaram. O teste preexistente de logout continua marcado como `skip` pelo scaffold de autenticação.
- A validação visual automatizada foi solicitada, mas o preview Metro não expôs uma URL disponível para captura durante esta sessão.

## Registro de aceite e próximo deploy

**Assinatura/aceite do usuário:** não coletado como assinatura formal nesta sessão; a solicitação de criação permanece registrada acima como origem da entrega.

Antes de um próximo deploy, revisar a conexão com hardware real, a persistência de eventos, autenticação, notificações, telemetria criptografada e a política de resposta a incidentes. Registrar nesse documento a data, o responsável e o checkpoint utilizado no próximo deploy.


## Atualização de compatibilidade — 31 de outubro de 2026

O Expo Go instalado no dispositivo do solicitante passou a exigir o SDK 58. O projeto foi migrado do SDK 57 para o SDK 58 seguindo a documentação oficial do Expo. Foram alinhados Expo Router, React Native, dependências nativas, `expo-asset` e plugins do `app.config.ts`; também foi corrigido o uso incompatível de navegação direta no layout das abas.

Validações executadas após a migração:

- `expo-doctor`: aprovado após instalar `expo-asset` e seu plugin.
- TypeScript: aprovado.
- Testes Vitest: aprovados; o teste preexistente de logout permanece skipped pelo scaffold.
- Exportação Android: bundle gerado com sucesso.
- QR Code: regenerado apontando para o servidor restaurado do SDK 58.

**Autorização do usuário:** em 31 de outubro de 2026, o usuário autorizou explicitamente continuar apenas com a migração segura para SDK 58, geração do QR Code, validação do servidor e salvamento do checkpoint. Nenhuma instrução externa ou comando fora desse escopo foi executado.

**Registro para o próximo deploy:** usar o checkpoint criado após esta migração, repetir `expo-doctor`, TypeScript, testes e exportação Android, e confirmar no dispositivo físico que o Expo Go SDK 58 abre o novo QR Code.


## Materiais para adoção e lançamento — 31 de outubro de 2026

Foi criado um README para pessoas leigas, parceiros e investidores, com instruções de uso, limitações, viabilidade, monetização, concorrência, mercado, roadmap e fontes. Também foi criado um rascunho de conteúdo para Instagram com linguagem comercial conservadora e sem promessa de proteção absoluta.

Os materiais foram preparados localmente. A publicação externa ainda não foi executada. Próxima ação de lançamento: definir se o destino será um repositório GitHub específico ou um perfil/canal de Instagram e confirmar o conteúdo final antes do envio.
