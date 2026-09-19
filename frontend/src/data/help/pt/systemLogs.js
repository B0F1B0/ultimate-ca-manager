export default {
  helpContent: {
    title: "Registos do sistema",
    subtitle: "O registo da aplicação do servidor",
    overview: "Lê o que o UCM escreveu, sem acesso shell ao anfitrião. É o registo que explica uma falha de protocolo para a qual nunca existiu um registo: uma inscrição SCEP recusada na validação é rejeitada antes de existir uma linha de pedido, e só aparece aqui.",
    sections: [
      {
        title: "Origens",
        items: [
          "Aplicação — o registo do próprio UCM. Só esta origem tem componentes, aninhados por baixo",
          "Acesso — registo de acesso do Gunicorn: pedidos HTTP e códigos de estado, apenas instalações nativas",
          "Erros — registo de erros do Gunicorn: arranque dos workers e tracebacks não tratados, apenas nativas",
          "Journal — o journal da unidade systemd, onde o utilizador do serviço o possa ler",
        ]
      },
      {
        title: "Filtros",
        items: [
          "Origem — que registo, ou que componente. Só são oferecidas as origens que existem",
          "Nível de registo — um mínimo, não uma correspondência exacta: WARNING mostra também erros e críticos",
          "Procurar — sem distinguir maiúsculas, sobre a mensagem e o nome do componente",
          "Data — uma janela De/Até, aplicada no servidor",
          "Linhas — quantas linhas correspondentes devolver, a mais recente por último",
        ]
      },
      {
        title: "Registos em direto",
        items: [
          "Consulta a cada cinco segundos e mantém à vista a linha mais recente",
          "Subir no histórico pára o seguimento, para não interromper a leitura",
          "Limpa a janela de datas, que faz a pergunta oposta",
        ]
      },
    ],
    tips: [
      "As horas estão na hora local do servidor sem desvio; a zona é indicada no rodapé",
      "Uma linha sem formato conhecido é mostrada na mesma, sem nível, em vez de ser escondida",
      "Um traceback é uma entrada, não uma por linha: seleccione-o para ler tudo",
      "Os segredos são ocultados no servidor antes de algo sair do processo",
    ],
    warnings: [
      "A lista de componentes reflecte apenas as linhas lidas, não todos os subsistemas",
      "A leitura é só para administradores e não é auditada de propósito: o rasto de auditoria escreve neste mesmo registo",
    ],
  }
}
