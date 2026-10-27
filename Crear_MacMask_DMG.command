#!/bin/bash
# Compila MacMask y crea un DMG local de prueba para Apple Silicon.
set -euo pipefail
cd "$(dirname "$0")"
finish() {
  code=$?
  if [ "$code" -ne 0 ]; then
    echo ""
    echo "ERROR: no se ha creado un instalador válido. Revisa el error anterior."
  fi
  echo ""
  read -r -p "Presiona Intro para cerrar… " _ || true
}
trap finish EXIT

if [ "$(uname -m)" != "arm64" ]; then echo "Este paquete requiere un Mac con chip Apple Silicon (serie M)."; exit 1; fi
if ! /usr/bin/xcodebuild -version >/dev/null 2>&1; then
  echo "Necesitas Xcode completo. Ábrelo una vez y acepta sus condiciones."; exit 1
fi
for file in MacMask.swift Info.plist Assets/Icono_MAC_13.png; do
  test -f "$file" || { echo "Falta archivo: $file"; exit 1; }
done

ROOT="$PWD/salida-local"
APP="$ROOT/MacMask.app"
STAGE="$ROOT/contenido-DMG"
DMG="$ROOT/MacMask-v1.6-Apple-Silicon-PRUEBA.dmg"
mkdir -p "$ROOT"
rm -rf "$APP" "$STAGE"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "[1/5] Compilando MacMask para Apple Silicon…"
/usr/bin/xcrun --sdk macosx swiftc -parse-as-library -O -target arm64-apple-macos15.0 \
 -framework SwiftUI -framework AppKit -framework CoreWLAN -framework CoreLocation -framework Combine \
 -o "$APP/Contents/MacOS/MacMask" MacMask.swift
cp Info.plist "$APP/Contents/Info.plist"
cp Assets/*.png "$APP/Contents/Resources/"
/usr/bin/iconutil -c icns MACMiniIcon.iconset -o "$APP/Contents/Resources/MACMiniIcon.icns"

echo "[2/5] Preparando firma…"
# Modo oficial: configurar TEAM_ID y SIGN_IDENTITY con un certificado Apple Developer ID Application.
# El helper NUNCA se instala sin verificación de firma válida.
if [ -n "${TEAM_ID:-}" ] && [ -n "${SIGN_IDENTITY:-}" ]; then
  if ! [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then echo "TEAM_ID inválido"; exit 1; fi
  mkdir -p "$APP/Contents/Library/LaunchDaemons" "$APP/Contents/MacOS"
  cp com.macmask.privileged.plist "$APP/Contents/Library/LaunchDaemons/"
  sed "s/__TEAM_ID__/$TEAM_ID/g" MacMaskPrivilegedHelper.swift > "$ROOT/.MacMaskPrivilegedHelper-compilar.swift"
  # Swift interpreta top-level main en el archivo principal llamado main.swift.
  cp "$ROOT/.MacMaskPrivilegedHelper-compilar.swift" "$ROOT/main.swift"
  /usr/bin/xcrun --sdk macosx swiftc -O -target arm64-apple-macos15.0 \
    -framework Foundation -framework Security \
    -o "$APP/Contents/MacOS/MacMaskPrivilegedHelper" "$ROOT/main.swift"
  /usr/bin/codesign --force --options runtime --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/MacMaskPrivilegedHelper"
  /usr/bin/codesign --force --deep --options runtime --sign "$SIGN_IDENTITY" "$APP"
else
  echo "Sin Team ID + certificado Developer ID: versión local, seguirá pidiendo contraseña."
  /usr/bin/codesign --force --sign - "$APP"
fi
/usr/bin/codesign --verify --strict "$APP"
test -x "$APP/Contents/MacOS/MacMask" || { echo "Falta el ejecutable"; exit 1; }

echo "[3/5] Preparando instalador…"
mkdir -p "$STAGE"
/usr/bin/ditto "$APP" "$STAGE/MacMask.app"
/bin/ln -s /Applications "$STAGE/Aplicaciones"

# El DMG contiene únicamente MacMask.app y el acceso directo Aplicaciones.
echo "[4/5] Creando DMG…"
rm -f "$DMG" "$DMG.sha256"
/usr/bin/hdiutil create -volname 'MacMask v1.6' -srcfolder "$STAGE" -format UDZO -ov "$DMG"
/usr/bin/hdiutil verify "$DMG"
/usr/bin/shasum -a 256 "$DMG" > "$DMG.sha256"
echo "[5/5] Listo."
echo ""
echo "Instalador de PRUEBA: $DMG"
echo "Para distribución pública: firma Developer ID y notarización son necesarias."
/usr/bin/open "$ROOT"
