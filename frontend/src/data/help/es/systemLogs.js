export default {
  helpContent: {
    title: "Registros del sistema",
    subtitle: "El registro de aplicación del servidor",
    overview: "Lee lo que UCM escribió, sin acceso de shell al host. Es el registro que explica un fallo de protocolo para el que nunca se creó un registro: una inscripción SCEP rechazada durante la validación se descarta antes de que exista una fila de solicitud, y solo aparece aquí.",
    sections: [
      {
        title: "Orígenes",
        items: [
          "Aplicación — el registro propio de UCM. Solo este origen tiene componentes, anidados debajo",
          "Acceso — registro de acceso de Gunicorn: peticiones HTTP y códigos de estado, solo instalaciones nativas",
          "Errores — registro de errores de Gunicorn: arranque de workers y trazas no gestionadas, solo nativas",
          "Journal — el journal de la unidad systemd, si el usuario del servicio puede leerlo",
        ]
      },
      {
        title: "Filtros",
        items: [
          "Origen — qué registro, o qué componente. Solo se ofrecen los orígenes que existen",
          "Nivel de registro — un mínimo, no una coincidencia exacta: WARNING muestra también errores y críticos",
          "Buscar — sin distinguir mayúsculas, sobre el mensaje y el nombre del componente",
          "Fecha — una ventana Desde/Hasta, aplicada en el servidor",
          "Líneas — cuántas líneas coincidentes devolver, la más reciente al final",
        ]
      },
      {
        title: "Registros en vivo",
        items: [
          "Consulta cada cinco segundos y mantiene a la vista la línea más reciente",
          "Desplazarse hacia arriba detiene el seguimiento, para no interrumpir la lectura",
          "Limpia la ventana de fechas, que plantea la pregunta opuesta",
        ]
      },
    ],
    tips: [
      "Las horas están en la hora local del servidor sin desfase; la zona se indica al pie",
      "Una línea sin formato conocido se muestra igualmente, sin nivel, en lugar de ocultarse",
      "Una traza es una entrada, no una por línea: selecciónela para leerla entera",
      "Los secretos se redactan en el servidor antes de salir del proceso",
    ],
    warnings: [
      "La lista de componentes refleja solo lo que aparece en las líneas leídas, no todo el sistema",
      "La lectura es solo para administradores y no se audita a propósito: el rastro de auditoría escribe en este mismo registro",
    ],
  }
}
