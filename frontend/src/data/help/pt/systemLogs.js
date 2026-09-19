export default {
  helpContent: {
    title: "Registos do sistema",
    subtitle: "O registo da aplicação do servidor",
    overview: "Lê o que o UCM escreveu, sem acesso shell ao anfitrião. É o registo que explica uma falha de protocolo para a qual nunca existiu um registo: uma inscrição SCEP recusada na validação é rejeitada antes de existir uma linha de pedido, e só aparece aqui.",
    sections: [
      {
        title: "Origens",
        items: [
          "Aplicação — o registo do próprio UCM. A única origem com componentes",
          "Acesso — registo de acesso do Gunicorn: pedidos HTTP e códigos de estado, apenas instalações nativas",
          "Erros — registo de erros do Gunicorn: arranque dos workers e tracebacks não tratados, apenas nativas",
          "Journal — o journal da unidade systemd, onde o utilizador do serviço o possa ler",
        ]
      },
      {
        title: "Filtros",
        items: [
          "Origem — Que registo é lido. Só são oferecidas as origens que esta instalação tem",
          "Componente — Um subsistema do registo da aplicação, ou todos. Estão todos, não só os visíveis",
          "Nível de registo — Um mínimo, não uma correspondência exacta: WARNING mostra também erros e críticos",
          "Procurar — Sem distinguir maiúsculas, sobre a mensagem e o nome do componente",
          "Excluir — Remove as linhas que correspondem: o mais rápido para calar um batimento",
          "Expressões regulares — Trata procurar e excluir como padrões; um incompleto não corresponde a nada",
          "Data — Uma janela De/Até, aplicada no servidor",
          "Linhas — Quantas linhas correspondentes devolver, da mais recente para a mais antiga",
        ]
      },
      {
        title: "Registos em direto",
        items: [
          "Consulta a cada cinco segundos; a linha mais recente é a primeira",
          "Limpa a janela de datas, que faz a pergunta oposta",
        ]
      },
    ],
    tips: [
      "As horas estão na hora local do servidor sem desvio; a zona é indicada no rodapé",
      "Uma linha sem formato conhecido é mostrada na mesma, sem nível, em vez de ser escondida",
      "Um traceback é uma entrada, não uma por linha: a célula da mensagem quebra e mostra-o inteiro",
      "Os segredos são ocultados no servidor antes de algo sair do processo",
    ],
    warnings: [
      "Um componente sem escrita recente continua listado: escolhê-lo pode não devolver nada",
      "A leitura é só para administradores e não é auditada de propósito: o rasto de auditoria escreve neste mesmo registo",
    ],
  },
  helpGuides: {
    title: "Registos do sistema",
    content: `
## Visão geral

Lê o que o UCM escreveu, sem acesso shell ao anfitrião. É o registo que explica uma falha para a qual nunca existiu um registo: uma inscrição SCEP recusada na validação é rejeitada antes de existir uma linha de pedido.

As linhas aparecem da mais recente para a mais antiga e todos os filtros são aplicados no servidor.

## Origens

**Origem** e **Componente** estão no painel de filtros: escolha o registo e depois restrinja a um subsistema.

- **Aplicação**: o registo do próprio UCM. A única origem com componentes.
- **Acesso**: registo de acesso do Gunicorn, apenas instalações nativas.
- **Erros**: registo de erros do Gunicorn, apenas instalações nativas.
- **Journal**: o journal do systemd, quando legível.

### Componentes

**Todos os componentes** é o registo da aplicação inteiro. A lista inclui todos os subsistemas a partir dos quais o UCM pode escrever, mesmo os que estiveram calados. Escolher um abrange tudo o que está por baixo: \`services\` cobre \`services.scep.scep_service\`.

## Filtros

### Nível de registo
Um mínimo, não uma correspondência exacta: **WARNING** mostra também erros e críticos. Uma linha sem nível legível nunca é escondida.

### Procurar e Excluir
Ambos percorrem a mensagem e o nome do componente. **Excluir** remove o que corresponde, a forma mais rápida de calar um batimento que se repete a cada minuto. **Expressões regulares** trata ambos como padrões; um padrão incompleto não corresponde a nada em vez de falhar.

### Data
Uma janela De/Até. Uma linha sem hora fica de fora: a janela pergunta por um instante.

### Linhas
Quantas linhas correspondentes devolver, de 100 a 5000.

## Registos em direto

Consulta a cada cinco segundos e limpa a janela de datas, que faz a pergunta oposta.

## Copiar

**Copiar tudo** leva todas as linhas; ao marcar alguma surge **Copiar selecção**. A cópia mantém a forma do registo.

## Ler o rodapé

- **A mostrar as N linhas mais recentes de M correspondentes** — corresponderam mais do que **Linhas** permite.
- **Apenas a parte mais recente do ficheiro foi lida** — o ficheiro excede a janela lida.

As horas não têm desvio: são hora local do servidor, e a zona aparece ao lado do caminho.

## Acesso

Apenas administradores, e deliberadamente não auditado: o rasto de auditoria escreve neste mesmo registo.
`
  }
}
