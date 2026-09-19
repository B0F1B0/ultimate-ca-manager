export default {
  helpContent: {
    title: "Registros del sistema",
    subtitle: "El registro de aplicación del servidor",
    overview: "Lee lo que UCM escribió, sin acceso de shell al host. Es el registro que explica un fallo de protocolo para el que nunca se creó un registro: una inscripción SCEP rechazada durante la validación se descarta antes de que exista una fila de solicitud, y solo aparece aquí.",
    sections: [
      {
        title: "Orígenes",
        items: [
          "Aplicación: el registro propio de UCM. Única fuente con componentes",
          "Acceso: registro de acceso de Gunicorn con las peticiones HTTP y los códigos de estado, solo instalaciones nativas",
          "Errores: registro de errores de Gunicorn con el arranque de los workers y las trazas no gestionadas, solo nativas",
          "Journal: el journal de la unidad systemd, si el usuario del servicio puede leerlo",
        ]
      },
      {
        title: "Filtros",
        items: [
          "Origen: qué registro se lee. Solo se ofrecen los orígenes que esta instalación tiene",
          "Componente: un subsistema del registro de aplicación, o todos. Están todos, no solo los visibles",
          "Nivel de registro: un mínimo, no una coincidencia exacta. WARNING muestra también errores y críticos",
          "Buscar: sin distinguir mayúsculas, sobre el mensaje y el nombre del componente. Es texto literal, no un patrón",
          "Excluir: quita las líneas que coinciden, lo más rápido para silenciar un latido",
          "Fecha: una ventana Desde/Hasta, aplicada en el servidor",
          "Líneas: cuántas líneas coincidentes devolver, de más reciente a más antigua",
        ]
      },
      {
        title: "Registros en vivo",
        items: [
          "Consulta cada cinco segundos; la línea más reciente es la primera",
          "Limpia la ventana de fechas, que plantea la pregunta opuesta",
        ]
      },
    ],
    tips: [
      "Las horas están en la hora local del servidor sin desfase; la zona se indica al pie",
      "Una línea sin formato conocido se muestra igualmente, sin nivel, en lugar de ocultarse",
      "Un rastreo es una entrada, no una por línea: la celda del mensaje se ajusta y lo muestra entero",
      "Los secretos se redactan en el servidor antes de salir del proceso",
    ],
    warnings: [
      "Un componente que no ha registrado nada recientemente sigue en la lista: elegirlo puede no devolver nada",
      "La lectura es solo para administradores y no se audita a propósito: el rastro de auditoría escribe en este mismo registro",
    ],
  },
  helpGuides: {
    title: "Registros del sistema",
    content: `
## Resumen

Lee lo que UCM escribió, sin acceso de shell al host. Es el registro que explica un fallo para el que nunca se creó un registro: una inscripción SCEP rechazada en la validación se descarta antes de que exista una fila de solicitud.

Las líneas se muestran de más reciente a más antigua y todos los filtros se aplican en el servidor.

## Orígenes

**Origen** y **Componente** están en el panel de filtros: elija el registro y luego acótelo a un subsistema.

- **Aplicación**: el registro propio de UCM. Único origen con componentes.
- **Acceso**: registro de acceso de Gunicorn, solo instalaciones nativas.
- **Errores**: registro de errores de Gunicorn, solo instalaciones nativas.
- **Journal**: el journal de systemd, si se puede leer.

### Componentes

**Todos los componentes** es el registro de aplicación completo. La lista incluye todos los subsistemas de los que UCM puede registrar, aunque lleven tiempo en silencio. Elegir uno abarca todo lo que hay debajo: \`services\` cubre \`services.scep.scep_service\`.

## Filtros

### Nivel de registro
Un mínimo, no una coincidencia exacta: **WARNING** muestra también errores y críticos. Una línea sin nivel legible nunca se oculta.

### Buscar y Excluir
Ambos recorren el mensaje y el nombre del componente. **Excluir** quita lo que coincide, la forma más rápida de silenciar un latido que se repite cada minuto.

Ambos son texto literal, no patrones: \`.*\` coincide con esos dos caracteres y nada más. Un patrón enviado desde el navegador sería trabajo sin límite para el único worker que responde aquí a todos los protocolos.

### Fecha
Una ventana Desde/Hasta. Una línea sin hora queda fuera: la ventana pregunta por un instante.

### Líneas
Cuántas líneas coincidentes devolver, de 100 a 5000.

## Registros en vivo

Consulta cada cinco segundos y limpia la ventana de fechas, que plantea la pregunta opuesta.

## Copiar

**Copiar todo** toma todas las líneas; al marcar alguna aparece **Copiar selección**. Se copia con la forma del registro.

## Leer el pie de página

- **Mostrando las N líneas más recientes de M coincidentes**: coincidieron más de las que permite **Líneas**.
- **Solo se leyó la parte más reciente del archivo**: el archivo supera la ventana leída.

Las horas no llevan desfase: son hora local del servidor, y la zona aparece junto a la ruta.

## Acceso

Solo administradores, y deliberadamente sin auditar: el rastro de auditoría se escribe en este mismo registro.
`
  }
}
