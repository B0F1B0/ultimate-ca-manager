export default {
  helpContent: {
    title: 'Descoberta de Certificados',
    subtitle: 'Encontre certificados TLS na sua rede',
    overview: 'Varra sua rede para encontrar certificados TLS implantados em servidores e endpoints e compará-los com o inventário da sua PKI gerenciada. Localize certificados não rastreados, detecte mudanças e monitore certificados expirando fora do controle do UCM.',
    sections: [
      {
        title: 'Abas',
        items: [
          { label: 'Descobertos', text: 'Todos os certificados encontrados pelas varreduras, com status, expiração e detalhes do endpoint' },
          { label: 'Perfis', text: 'Configurações de varredura salvas, alvos, portas, agendamento, notificações' },
          { label: 'Histórico', text: 'Execuções de varredura passadas com duração, alvos varridos e certificados encontrados' },
        ]
      },
      {
        title: 'Varredura',
        items: [
          { label: 'Varredura Rápida', text: 'Varredura ad-hoc sem salvar um perfil, insira alvos e portas, os resultados chegam ao vivo' },
          { label: 'Alvos', text: 'Um por linha: hostname, IP, sub-rede CIDR (192.168.1.0/24) ou host:port (10.0.0.1:8443)' },
          { label: 'Portas', text: 'Portas TCP separadas por vírgula (ex. 443, 8443, 636), ou a predefinição de portas comuns' },
          { label: 'Opções avançadas', text: 'Resolução DNS reversa (registros PTR), timeout e concorrência' },
          { label: 'Agendamento', text: 'Os perfis executam manualmente ou automaticamente a cada 1h / 6h / 12h / 24h / 7d' },
          { label: 'Notificações', text: 'Alertas por e-mail sobre novos certificados, mudanças de certificado ou expiração próxima' },
        ]
      },
      {
        title: 'Status dos Resultados',
        items: [
          { label: 'Gerenciado', text: 'A impressão digital SHA-256 do certificado corresponde a um certificado no inventário do UCM' },
          { label: 'Não gerenciado', text: 'Encontrado na rede mas não no inventário, candidato a ser trazido para gerenciamento' },
          { label: 'Erro', text: 'O endpoint não pôde ser varrido, a dica de erro distingue conexão recusada, DNS, timeout e falhas TLS/SNI; tente novamente individualmente ou todos de uma vez' },
          { label: 'Alterado', text: 'Um endpoint apresentando um certificado diferente da varredura anterior é marcado com um timestamp de Última alteração' },
        ]
      },
    ],
    tips: [
      'Filtre os resultados com os marcadores de status: Gerenciado, Não gerenciado, Erro, Expirado, Expirando em Breve',
      'Exporte os certificados descobertos como CSV ou JSON: os filtros ativos se aplicam à exportação',
      'Agende uma varredura diária das sub-redes dos seus servidores com a notificação de novos certificados ativada',
    ],
    warnings: [
      'Executar varreduras e gerenciar perfis requer permissões de administrador; sub-redes são limitadas a 1024 endereços (/22)',
    ],
  },
  helpGuides: {
    title: 'Descoberta de Certificados',
    content: `
## Visão Geral

A Descoberta de Certificados varre sua rede para encontrar certificados TLS implantados em servidores e endpoints e compará-los com o inventário da sua PKI gerenciada. Use-a para localizar certificados não rastreados, detectar mudanças e monitorar certificados expirando fora do controle do UCM.

## Abas

### Descobertos
Todos os certificados encontrados pelas varreduras, com status, expiração e detalhes do endpoint. Clique em uma linha para abrir o painel de detalhes com informações do certificado, Subject Alternative Names e histórico de varreduras (visto pela primeira vez, visto pela última vez, última alteração).

### Perfis
Configurações de varredura salvas para varreduras recorrentes: alvos, portas, agendamento e notificações.

### Histórico
Execuções de varredura passadas com duração, alvos varridos, certificados encontrados e quem disparou a execução.

## Varredura Rápida

Execute uma varredura ad-hoc sem salvar um perfil:

1. Clique em **Varredura Rápida**
2. Insira os **alvos**: um por linha: hostname, IP, sub-rede CIDR (\`192.168.1.0/24\`) ou \`host:port\` (\`10.0.0.1:8443\`)
3. Insira as **portas**: portas TCP separadas por vírgula (ex. \`443, 8443, 636\`), ou escolha a predefinição de portas comuns
4. Opcionalmente ajuste as **opções avançadas**: resolução DNS reversa (registros PTR), timeout, concorrência
5. Clique em **Iniciar Varredura**: o progresso é atualizado ao vivo via WebSocket

## Perfis de Varredura

Os perfis salvam uma configuração de alvos para uso repetido:

- **Alvos e portas**: mesmos formatos da Varredura Rápida
- **Agendamento**: manual, ou automático a cada 1h / 6h / 12h / 24h / 7d
- **Notificações**: alertas por e-mail quando novos certificados são descobertos, quando um certificado muda em um endpoint ou quando certificados descobertos estão expirando

Execute um perfil sob demanda com **Varrer**, ou deixe o agendador executá-lo no intervalo configurado.

## Status dos Resultados

- **Gerenciado**: A impressão digital SHA-256 do certificado corresponde a um certificado no inventário do UCM
- **Não gerenciado**: Encontrado na rede mas não no inventário: candidato a ser trazido para gerenciamento
- **Erro**: O endpoint não pôde ser varrido; a coluna de erro mostra uma dica (conexão recusada, falha de DNS, timeout, problema de handshake TLS / SNI)

### Detecção de Mudanças
Quando um endpoint apresenta um certificado diferente da varredura anterior, a mudança é registrada (impressão digital anterior mantida, timestamp de **Última alteração**) e pode disparar uma notificação.

## Filtragem e Exportação

- **Marcadores de filtro de status**: Gerenciado, Não gerenciado, Erro, Expirado, Expirando em Breve
- **Filtro de perfil**: Restringir os resultados a um perfil de varredura
- **Exportar**: Baixar os certificados descobertos como CSV ou JSON (os filtros se aplicam)
- **Tentar novamente**: Varrer novamente alvos com erro individualmente, ou **Repetir todos os erros** de uma vez
- **Resolver DNS**: Resolução DNS reversa em massa para os IPs descobertos

## Limites e Segurança

- Sub-redes são limitadas a 1024 endereços (equivalente a um /22 IPv4); até 1000 alvos por varredura de perfil
- Faixas privadas RFC1918 e loopback são varríveis: o modelo de implantação on-prem do UCM; faixas link-local, multicast e reservadas são bloqueadas
- Todas as ações de varredura são registradas na auditoria

## Permissões

- **read:certificates**: Visualizar certificados descobertos, perfis e histórico
- **admin:system**: Criar/editar perfis e executar varreduras
- **delete:certificates**: Excluir resultados descobertos

> 💡 Agende uma varredura diária das sub-redes dos seus servidores e ative a notificação de novos certificados: ela captura certificados implantados fora do seu processo de PKI.
`
  }
}
