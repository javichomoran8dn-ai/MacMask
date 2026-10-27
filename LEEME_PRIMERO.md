# MacMask v1.6 — Autorización única (proyecto en evaluación)

Se mantiene el diseño oscuro y las funciones de v1.5. Se añadió arquitectura de servicio auxiliar privilegiado (SMAppService + NSXPCConnection) que **necesita firma real de Apple Developer ID Application y pruebas en macOS**.

## Modos de compilación
- Abrir `Crear_MacMask_DMG.command` normalmente: genera MacMask de PRUEBA con firma local; **la contraseña se seguirá solicitando** para cambiar/restaurar/reiniciar la red. Es el comportamiento seguro de compatibilidad.
- Para el servicio auxiliar: desde Terminal, dentro de esta carpeta, configurar `TEAM_ID` (equipo Apple de 10 caracteres) y `SIGN_IDENTITY` (identidad real de Developer ID Application) al ejecutar el script. Ejemplo conceptual: `TEAM_ID=XXXXXXXXXX SIGN_IDENTITY="Developer ID Application: ..." ./Crear_MacMask_DMG.command`.
- Solo con firma verificada, abrir Ajustes de MacMask y usar «Configurar autorización única». macOS puede solicitar aprobación inicial del daemon desde Ajustes del Sistema → General → Ítems de inicio y extensiones. No se almacena la contraseña.

## Avisos de seguridad
El helper valida la firma del cliente, verifica la interfaz Wi-Fi en el sistema, y permite **solamente** `change` y `reconnect` con MAC y argumentos controlados, nunca comandos de texto arbitrarios. La app sigue comprobando la MAC observada antes de mostrar éxito. Este código no se ha compilado ni probado en macOS desde el entorno de creación; la funcionalidad sin contraseña no está confirmada aún. La firma ad-hoc no habilita la autorización única. No distribuir como una versión de producción hasta validar la instalación y protección XPC, compilación y notarización.
