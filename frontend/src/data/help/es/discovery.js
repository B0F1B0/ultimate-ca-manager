export default {
  helpContent: {
    title: 'Descubrimiento de certificados',
    subtitle: 'Encuentre los certificados TLS de su red',
    overview: 'Analice su red para encontrar los certificados TLS desplegados en servidores y endpoints, y compárelos con su inventario PKI gestionado. Localice certificados no rastreados, detecte cambios y vigile los certificados por expirar fuera del control de UCM.',
    sections: [
      {
        title: 'Pestañas',
        items: [
          { label: 'Descubiertos', text: 'Todos los certificados encontrados por los escaneos, con estado, expiración y detalles del endpoint' },
          { label: 'Perfiles', text: 'Configuraciones de escaneo guardadas, objetivos, puertos, programación, notificaciones' },
          { label: 'Historial', text: 'Ejecuciones pasadas con duración, objetivos analizados y certificados encontrados' },
        ]
      },
      {
        title: 'Escaneo',
        items: [
          { label: 'Escaneo rápido', text: 'Escaneo puntual sin guardar un perfil, introduzca objetivos y puertos, los resultados llegan en directo' },
          { label: 'Objetivos', text: 'Uno por línea: nombre de host, IP, subred CIDR (192.168.1.0/24) o host:port (10.0.0.1:8443)' },
          { label: 'Puertos', text: 'Puertos TCP separados por comas (p. ej. 443, 8443, 636), o el preajuste de puertos comunes' },
          { label: 'Opciones avanzadas', text: 'Resolución DNS inversa (registros PTR), tiempo de espera y concurrencia' },
          { label: 'Programación', text: 'Los perfiles se ejecutan manualmente o automáticamente cada 1h / 6h / 12h / 24h / 7d' },
          { label: 'Notificaciones', text: 'Alertas por correo sobre nuevos certificados, cambios de certificado o expiración inminente' },
        ]
      },
      {
        title: 'Estados de los resultados',
        items: [
          { label: 'Gestionado', text: 'La huella SHA-256 del certificado coincide con un certificado del inventario de UCM' },
          { label: 'No gestionado', text: 'Encontrado en la red pero ausente del inventario, candidato a incorporarse a la gestión' },
          { label: 'Error', text: 'El endpoint no pudo analizarse, la pista de error distingue rechazo, DNS, tiempo agotado y fallos TLS/SNI; reintente individualmente o todos a la vez' },
          { label: 'Cambiado', text: 'Un endpoint que presenta un certificado diferente al del escaneo anterior se marca con una marca de tiempo Último cambio' },
        ]
      },
    ],
    tips: [
      'Filtre los resultados con las píldoras de estado: Gestionado, No gestionado, Error, Expirado, Por expirar',
      'Exporte los certificados descubiertos como CSV o JSON: los filtros activos se aplican a la exportación',
      'Programe un escaneo diario de sus subredes de servidores con la notificación de nuevo certificado activada',
    ],
    warnings: [
      'Lanzar escaneos y gestionar perfiles requiere permisos de administrador; las subredes están limitadas a 1024 direcciones (/22)',
    ],
  },
  helpGuides: {
    title: 'Descubrimiento de certificados',
    content: `
## Descripción general

El descubrimiento de certificados analiza su red para encontrar los certificados TLS desplegados en servidores y endpoints, y los compara con su inventario PKI gestionado. Úselo para localizar certificados no rastreados, detectar cambios y vigilar los certificados por expirar fuera del control de UCM.

## Pestañas

### Descubiertos
Todos los certificados encontrados por los escaneos, con estado, expiración y detalles del endpoint. Haga clic en una fila para abrir el panel de detalle con la información del certificado, los Subject Alternative Names y el historial de escaneo (primera detección, última detección, último cambio).

### Perfiles
Configuraciones de escaneo guardadas para análisis recurrentes: objetivos, puertos, programación y notificaciones.

### Historial
Ejecuciones pasadas con duración, objetivos analizados, certificados encontrados y quién lanzó la ejecución.

## Escaneo rápido

Ejecute un escaneo puntual sin guardar un perfil:

1. Haga clic en **Escaneo rápido**
2. Introduzca los **objetivos**: uno por línea: nombre de host, IP, subred CIDR (\`192.168.1.0/24\`) o \`host:port\` (\`10.0.0.1:8443\`)
3. Introduzca los **puertos**: puertos TCP separados por comas (p. ej. \`443, 8443, 636\`), o elija el preajuste de puertos comunes
4. Opcionalmente ajuste las **opciones avanzadas**: resolución DNS inversa (registros PTR), tiempo de espera, concurrencia
5. Haga clic en **Iniciar escaneo**: el progreso se actualiza en directo vía WebSocket

## Perfiles de escaneo

Los perfiles guardan una configuración de objetivos para uso repetido:

- **Objetivos y puertos**: mismos formatos que el escaneo rápido
- **Programación**: manual, o automática cada 1h / 6h / 12h / 24h / 7d
- **Notificaciones**: alertas por correo cuando se descubren nuevos certificados, cuando un certificado cambia en un endpoint o cuando los certificados descubiertos están por expirar

Ejecute un perfil bajo demanda con **Escanear**, o deje que el planificador lo ejecute en el intervalo configurado.

## Estados de los resultados

- **Gestionado**: La huella SHA-256 del certificado coincide con un certificado del inventario de UCM
- **No gestionado**: Encontrado en la red pero ausente del inventario: candidato a incorporarse a la gestión
- **Error**: El endpoint no pudo analizarse; la columna de error muestra una pista (conexión rechazada, fallo DNS, tiempo agotado, problema de handshake TLS / SNI)

### Detección de cambios
Cuando un endpoint presenta un certificado diferente al del escaneo anterior, el cambio se registra (se conserva la huella anterior, marca de tiempo **Último cambio**) y puede desencadenar una notificación.

## Filtrado y exportación

- **Píldoras de filtro por estado**: Gestionado, No gestionado, Error, Expirado, Por expirar
- **Filtro por perfil**: Restrinja los resultados a un perfil de escaneo
- **Exportar**: Descargue los certificados descubiertos como CSV o JSON (los filtros se aplican)
- **Reintentar**: Vuelva a escanear objetivos en error individualmente, o **Reintentar todos los errores** a la vez
- **Resolver DNS**: Resolución DNS inversa en bloque para las IP descubiertas

## Límites y seguridad

- Las subredes están limitadas a 1024 direcciones (equivalente a una /22 IPv4); hasta 1000 objetivos por escaneo de perfil
- Los rangos privados RFC1918 y loopback son escaneables: el modelo de despliegue on-premise de UCM; los rangos link-local, multicast y reservados están bloqueados
- Todas las acciones de escaneo se registran en la auditoría

## Permisos

- **read:certificates**: Ver certificados descubiertos, perfiles e historial
- **admin:system**: Crear/editar perfiles y lanzar escaneos
- **delete:certificates**: Eliminar resultados descubiertos

> 💡 Programe un escaneo diario de sus subredes de servidores y active la notificación de nuevo certificado: detecta los certificados desplegados fuera de su proceso PKI.
`
  }
}
