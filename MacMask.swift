import SwiftUI
import AppKit
import Foundation
import CoreWLAN
import CoreLocation
import Combine
import Darwin
import ServiceManagement

// Aplicación de uso local: no guarda contraseñas ni cambia la MAC de fábrica.
@main
struct MacMaskApp: App {
    var body: some Scene {
        WindowGroup("MacMask") {
            MainView()
                .frame(width: 820, height: 640)
                .background(FixedWindowConfigurator().frame(width: 0, height: 0))
        }
        .defaultSize(width: 820, height: 640)
        .windowResizability(.contentSize)
    }
}

struct WiFiSnapshot {
    let device: String
    let hardwareMAC: String
    let activeMAC: String
    let network: String
}

struct CommandResult {
    let code: Int32
    let output: String
}

// El servicio privilegiado solo funciona con firma Apple Developer válida.
// Nunca almacenamos credenciales. La versión local sin firma conserva el diálogo anterior.
@objc protocol MacMaskHelperProtocol {
    func perform(_ operation: String, mac: String, device: String,
                 reply: @escaping (Int32, String) -> Void)
}

private enum PrivilegedService {
    static let plistName = "com.macmask.privileged.plist"
    static let machName = "com.macmask.privileged"

    static var status: SMAppService.Status {
        SMAppService.daemon(plistName: plistName).status
    }
    static func register() -> String {
        do {
            try SMAppService.daemon(plistName: plistName).register()
            return "Registro solicitado. Si macOS requiere aprobación, ve a Ajustes del Sistema → General → Ítems de inicio y extensiones."
        } catch {
            return "No se pudo registrar el servicio: \(error.localizedDescription). Es necesaria una firma de desarrollador válida."
        }
    }
    static func perform(_ action: String, _ mac: String, _ device: String) -> CommandResult? {
        guard status == .enabled else { return nil }
        let connection = NSXPCConnection(machServiceName: machName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: MacMaskHelperProtocol.self)
        let gate = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var response = CommandResult(code: -1, output: "El servicio no respondió.")
        let fail: (Error) -> Void = { error in
            lock.lock(); response = CommandResult(code: -1, output: error.localizedDescription); lock.unlock()
            gate.signal()
        }
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler(fail) as? MacMaskHelperProtocol
        guard let proxy else { connection.invalidate(); return CommandResult(code: -1, output: "Servicio auxiliar incompatible.") }
        proxy.perform(action, mac: mac, device: device) { code, output in
            lock.lock(); response = CommandResult(code: code, output: output); lock.unlock()
            gate.signal()
        }
        let waited = gate.wait(timeout: .now() + 20)
        connection.invalidate()
        if waited == .timedOut { return CommandResult(code: -1, output: "El servicio tardó demasiado en responder.") }
        lock.lock(); defer { lock.unlock() }
        return response
    }
}

private enum SystemHelper {
    static func run(_ executable: String, _ arguments: [String]) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return CommandResult(code: process.terminationStatus,
                                 output: String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            return CommandResult(code: -1, output: error.localizedDescription)
        }
    }

    // Consulta de bajo nivel del enlace (AF_LINK): refleja la MAC de la interfaz,
    // sin depender del formato localizado de la salida de ifconfig.
    static func readInterfaceMAC(_ device: String) -> String? {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let head = interfaces else { return nil }
        defer { freeifaddrs(head) }
        var item: UnsafeMutablePointer<ifaddrs>? = head
        while let current = item {
            defer { item = current.pointee.ifa_next }
            let record = current.pointee
            guard String(cString: record.ifa_name) == device,
                  let address = record.ifa_addr,
                  Int32(address.pointee.sa_family) == AF_LINK else { continue }
            let linkAddress = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_dl.self).pointee
            let prefixLength = Int(linkAddress.sdl_nlen)
            let addressLength = Int(linkAddress.sdl_alen)
            let dataBytes = withUnsafeBytes(of: linkAddress.sdl_data) { Array($0) }
            guard addressLength == 6,
                  prefixLength >= 0,
                  prefixLength + addressLength <= dataBytes.count else { continue }
            let mac = dataBytes[prefixLength..<(prefixLength + addressLength)]
                .map { String(format: "%02X", $0) }.joined(separator: ":")
            if normalizeMAC(mac) != nil && mac != "02:00:00:00:00:00" { return mac }
        }
        return nil
    }

    static func observedMAC(_ device: String) -> String? {
        let interfaceOutput = run("/sbin/ifconfig", [device]).output
        let fromIfconfig = firstCapture(#"(?i)\bether\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})"#, in: interfaceOutput)?.uppercased()
        let fromLink = readInterfaceMAC(device)
        // Priorizar direcciones legibles distintas del placeholder de privacidad.
        // AF_LINK es una segunda lectura independiente del comando externo.
        if let fromIfconfig, normalizeMAC(fromIfconfig) != nil,
           fromIfconfig != "02:00:00:00:00:00" { return fromIfconfig }
        if let fromLink { return fromLink }
        return nil
    }

    static func capture() -> WiFiSnapshot? {
        let listing = run("/usr/sbin/networksetup", ["-listallhardwareports"]).output
        let groups = listing.components(separatedBy: "\n\n")
        guard let group = groups.first(where: { block in
            block.localizedCaseInsensitiveContains("Hardware Port: Wi-Fi") ||
            block.localizedCaseInsensitiveContains("Hardware Port: AirPort")
        }) else { return nil }
        let rows = group.components(separatedBy: .newlines)
        guard let deviceLine = rows.first(where: { $0.hasPrefix("Device:") }),
              let device = deviceLine.split(separator: ":", maxSplits: 1).last.map(String.init)?.trimmingCharacters(in: .whitespaces),
              device.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil else { return nil }
        let hardware = rows.first(where: { $0.hasPrefix("Ethernet Address:") })?
            .split(separator: ":", maxSplits: 1).last.map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "Desconocida"
        let active = observedMAC(device) ?? "No disponible"
        // CoreWLAN consulta la red real; en macOS moderno el SSID necesita permiso
        // de ubicación. Evitamos interpretar «no asociado» como desconexión segura.
        var detectedSSID = CWWiFiClient.shared().interface(withName: device)?.ssid()
        if detectedSSID?.isEmpty ?? true {
            let output = run("/usr/sbin/networksetup", ["-getairportnetwork", device]).output
            if output.hasPrefix("Current Wi-Fi Network:") {
                detectedSSID = String(output.dropFirst("Current Wi-Fi Network:".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        let network = detectedSSID?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return WiFiSnapshot(device: device, hardwareMAC: hardware.uppercased(),
                            activeMAC: active.uppercased(), network: network)
    }

    private static func firstCapture(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[range])
    }

    static func normalizeMAC(_ text: String) -> String? {
        let candidate = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: ":").uppercased()
        guard candidate.range(of: #"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$"#, options: .regularExpression) != nil else { return nil }
        let first = UInt8(candidate.prefix(2), radix: 16)!
        // Se requieren direcciones unicast; se permite una dirección global escrita por el usuario.
        guard (first & 0x01) == 0, candidate != "00:00:00:00:00:00" else { return nil }
        return candidate
    }

    static func randomSimilarMAC(to hardware: String) -> String? {
        guard let base = normalizeMAC(hardware) else { return nil }
        let parts = base.split(separator: ":")
        guard parts.count == 6 else { return nil }
        // Mantener el prefijo es una simulación de apariencia de fábrica: puede causar conflictos.
        // Evitar la coincidencia exacta con la MAC del hardware.
        for _ in 0..<8 {
            let suffix = (0..<3).map { _ in String(format: "%02X", UInt8.random(in: 0...255)) }
            let generated = (parts.prefix(3).map(String.init) + suffix).joined(separator: ":")
            if generated != base { return generated }
        }
        return nil
    }

    static func randomMAC() -> String {
        var bytes = (0..<6).map { _ in UInt8.random(in: 0...255) }
        bytes[0] = (bytes[0] | 0x02) & 0xFE // local y unicast
        return bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    // macOS solicita la clave de administrador. No la recibe ni almacena esta app.
    static func privileged(_ commands: String) -> CommandResult {
        let script = "do shell script \"\(commands.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"
        return run("/usr/bin/osascript", ["-e", script])
    }

    static func changeMAC(_ mac: String, device: String) -> CommandResult {
        // Solo argumentos validados por normalizeMAC/capture; nada de entrada libre en comandos.
        guard normalizeMAC(mac) != nil,
              device.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil else {
            return CommandResult(code: -1, output: "MAC o interfaz incorrecta.")
        }
        // Algunas versiones aceptan ifconfig después de reactivar Wi-Fi y antes de asociarse.
        // Otras no: se captura el error y se verifica el resultado; nunca se promete éxito.
        let cmd = "/usr/sbin/networksetup -setairportpower \(device) off && " +
                  "/usr/sbin/networksetup -setairportpower \(device) on && " +
                  "/sbin/ifconfig \(device) ether \(mac.lowercased())"
        if let result = PrivilegedService.perform("change", mac, device) { return result }
        return privileged(cmd)
    }

    static func reconnect(_ device: String) -> CommandResult {
        guard device.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil else {
            return CommandResult(code: -1, output: "Interfaz incorrecta.")
        }
        if let result = PrivilegedService.perform("reconnect", "", device) { return result }
        return privileged("/usr/sbin/networksetup -setairportpower \(device) off && /usr/sbin/networksetup -setairportpower \(device) on")
    }
}

enum GenerationMode: String, CaseIterable, Identifiable {
    case similar = "Similar"
    case privateRandom = "Privada aleatoria"
    var id: String { rawValue }
}

@MainActor
final class MACModel: ObservableObject {
    @Published var snapshot: WiFiSnapshot?
    @Published var input = ""
    @Published var generationMode: GenerationMode = .privateRandom
    @Published var message = "Identificando el adaptador Wi-Fi…"
    @Published var busy = false
    @Published var isError = false
    @Published var lastUpdatedAt: Date?
    @Published var successNotice: SuccessNotice?

    struct SuccessNotice: Identifiable {
        let id = UUID()
        let title: String
        let mac: String
    }

    init() { refresh() }

    func refresh(silent: Bool = false) {
        Task {
            let found = await Task.detached(priority: .userInitiated) { SystemHelper.capture() }.value
            snapshot = found
            lastUpdatedAt = Date()
            // Proponer una dirección al abrir la app; nunca se aplica automáticamente.
            if input.isEmpty, found != nil {
                input = generateValue() ?? ""
            }
            if !silent {
                if found == nil {
                    message = "No se detectó un adaptador Wi-Fi. Revisa los ajustes del sistema."
                    isError = true
                } else {
                    message = "Datos actualizados de \(found!.device)."
                    isError = false
                }
            }
        }
    }

    private func generateValue() -> String? {
        switch generationMode {
        case .similar:
            guard let hardware = snapshot?.hardwareMAC else { return nil }
            return SystemHelper.randomSimilarMAC(to: hardware)
        case .privateRandom:
            return SystemHelper.randomMAC()
        }
    }

    func generate() {
        guard let next = generateValue() else {
            isError = true
            message = "No se pudo leer la MAC original. Pulsa Actualizar o usa el modo Aleatoria."
            return
        }
        input = next
        isError = false
        message = generationMode == .similar
            ? "Dirección similar generada. No está asignada por Apple; todavía no se aplicó."
            : "Dirección privada aleatoria generada. Todavía no se aplicó."
    }

    func copyOriginalMAC() {
        guard let mac = snapshot?.hardwareMAC, SystemHelper.normalizeMAC(mac) != nil else {
            isError = true
            message = "No se pudo leer la dirección de fábrica. Pulsa Consultar MAC."
            return
        }
        NSPasteboard.general.clearContents()
        let copied = NSPasteboard.general.setString(mac, forType: .string)
        isError = !copied
        message = copied ? "MAC original copiada: \(mac)" : "No se pudo copiar la MAC original."
    }

    func copyTerminalCommand() {
        guard let device = snapshot?.device,
              device.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil else {
            isError = true
            message = "Primero detecta el adaptador pulsando Actualizar."
            return
        }
        // Copia un comando de solo lectura; nunca lo ejecuta automáticamente.
        let command = "ifconfig \(device) | grep ether"
        NSPasteboard.general.clearContents()
        let copied = NSPasteboard.general.setString(command, forType: .string)
        isError = !copied
        message = copied ? "Comando copiado: \(command). Pégalo en Terminal y presiona Enter." : "No se pudo copiar el comando."
    }

    func copyCurrentMAC() {
        guard let mac = snapshot?.activeMAC,
              mac != "02:00:00:00:00:00",
              SystemHelper.normalizeMAC(mac) != nil else {
            isError = true
            message = "No hay una MAC detectada para copiar. Pulsa Actualizar."
            return
        }
        NSPasteboard.general.clearContents()
        let copied = NSPasteboard.general.setString(mac, forType: .string)
        isError = !copied
        message = copied ? "MAC detectada copiada: \(mac)" : "No se pudo copiar la MAC."
    }

    func apply(autoGenerate: Bool = false, restore: Bool = false) {
        guard !busy, let snapshot else { return }
        if autoGenerate {
            guard let generated = generateValue() else {
                isError = true
                message = "No se pudo generar una MAC en el modo elegido."
                return
            }
            input = generated
        }
        let target = restore ? snapshot.hardwareMAC : input
        guard let mac = SystemHelper.normalizeMAC(target) else {
            isError = true
            message = "No hay una MAC generada válida. Pulsa el botón para generar otra."
            return
        }
        busy = true
        isError = false
        message = "Aplicando el cambio con autorización de macOS…"
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                SystemHelper.changeMAC(mac, device: snapshot.device)
            }.value
            var newest = await Task.detached(priority: .userInitiated) { SystemHelper.capture() }.value
            if result.code == 0 && newest?.activeMAC.caseInsensitiveCompare(mac) != .orderedSame {
                try? await Task.sleep(for: .milliseconds(900))
                newest = await Task.detached(priority: .userInitiated) { SystemHelper.capture() }.value
            }
            self.snapshot = newest
            self.lastUpdatedAt = Date()
            self.busy = false
            if result.code == 0 && newest?.activeMAC.caseInsensitiveCompare(mac) == .orderedSame {
                self.isError = false
                self.message = "MAC aplicada en \(snapshot.device): \(mac). La verificación en el router es independiente."
                self.successNotice = SuccessNotice(
                    title: restore ? "¡Restauración exitosa!" : "¡Cambio exitoso!",
                    mac: mac
                )
            } else {
                self.isError = true
                let details = result.output.isEmpty ? "La interfaz todavía no muestra la MAC solicitada." : result.output
                self.message = "Cambio no verificado. Dirección solicitada: \(mac). \(details)"
            }
        }
    }

    func reconnect() {
        guard !busy, let device = snapshot?.device else { return }
        busy = true
        isError = false
        message = "Reiniciando el adaptador Wi-Fi…"
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                SystemHelper.reconnect(device)
            }.value
            snapshot = await Task.detached(priority: .userInitiated) { SystemHelper.capture() }.value
            lastUpdatedAt = Date()
            busy = false
            isError = result.code != 0
            message = result.code == 0
                ? "Wi-Fi reactivado. La reconexión puede requerir unos segundos."
                : "No se pudo reiniciar Wi-Fi: \(result.output)"
        }
    }

    func openWiFiSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.wifi-settings-extension") {
            NSWorkspace.shared.open(url)
        } else {
            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/System Settings.app"))
        }
    }
}






// Permiso de ubicación: macOS lo exige para revelar el nombre (SSID) del Wi-Fi.
// Esta app NO solicita ni guarda coordenadas.
@MainActor
final class WiFiNamePermission: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var status: CLAuthorizationStatus
    private let manager = CLLocationManager()
    var onAuthorizationChange: (() -> Void)?

    override init() {
        status = .notDetermined
        super.init()
        status = manager.authorizationStatus
        manager.delegate = self
    }

    var allowed: Bool { status == .authorizedAlways }
    var denied: Bool { status == .denied || status == .restricted }

    func request() { manager.requestWhenInUseAuthorization() }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in
            self.status = manager.authorizationStatus
            self.onAuthorizationChange?()
        }
    }
}

// Efecto vidrio nativo que mezcla el color de la ventana con el escritorio.
struct GlassMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .hudWindow
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }
    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {}
}

struct FixedWindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { WindowConfigView() }
    func updateNSView(_ nsView: NSView, context: Context) {}

    final class WindowConfigView: NSView {
        private var configured = false
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, !configured else { return }
            configured = true
            window.minSize = NSSize(width: 820, height: 640)
            window.maxSize = NSSize(width: 820, height: 640)
            window.setContentSize(NSSize(width: 820, height: 640))
            window.styleMask.remove(.resizable)
            window.styleMask.insert(.fullSizeContentView)
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.isOpaque = false
            window.backgroundColor = .clear
            window.collectionBehavior.insert(.fullScreenNone)
            window.standardWindowButton(.zoomButton)?.isHidden = true
            window.center()
        }
    }
}

private enum ProPalette {
    static let cyan = Color(red: 0.02, green: 0.70, blue: 0.98)
    static let blue = Color(red: 0.025, green: 0.38, blue: 0.89)
    static let violet = Color(red: 0.15, green: 0.28, blue: 0.75)
    static let pink = Color(red: 0.08, green: 0.36, blue: 0.86)
    static let glass = Color(red: 0.052, green: 0.091, blue: 0.148)
    static let border = Color(red: 0.27, green: 0.43, blue: 0.66).opacity(0.62)
    static let subdued = Color.white.opacity(0.69)
    static let brandGradient = LinearGradient(
        colors: [Color(red: 0.03, green: 0.63, blue: 0.98),
                 Color(red: 0.025, green: 0.36, blue: 0.91)],
        startPoint: .leading, endPoint: .trailing)
}

struct MainView: View {
    @StateObject private var model = MACModel()
    @StateObject private var permission = WiFiNamePermission()
    @AppStorage("MacMaskConfirmNetworkChanges") private var confirmChanges = true
    private var secondaryText: Color { Color.white.opacity(0.68) }
    @State private var pendingAction: PendingAction?
    @State private var showSettings = false
    @State private var serviceStatusMessage = ""
    private let clock = Timer.publish(every: 15, on: .main, in: .common).autoconnect()

    private enum PendingAction: String, Identifiable {
        case apply, restore, restart
        var id: String { rawValue }
    }

    private var currentMAC: String {
        guard let mac = model.snapshot?.activeMAC,
              mac != "02:00:00:00:00:00" else { return "No disponible" }
        return mac
    }
    private var networkName: String? {
        guard let name = model.snapshot?.network, !name.isEmpty else { return nil }
        return name
    }
    private var selectedValid: Bool { SystemHelper.normalizeMAC(model.input) != nil }
    private var canChange: Bool { !model.busy && model.snapshot != nil && selectedValid }
    private var device: String { model.snapshot?.device ?? "Wi-Fi" }

    var body: some View {
        ZStack {
            LinearGradient(colors: [
                Color(red: 0.008, green: 0.019, blue: 0.037),
                Color(red: 0.012, green: 0.030, blue: 0.058),
                Color(red: 0.006, green: 0.014, blue: 0.031)
            ], startPoint: .topLeading, endPoint: .bottomTrailing)
            .ignoresSafeArea()

            VStack(spacing: 12) {
                header
                HStack(spacing: 12) {
                    macCard("MAC actual", value: currentMAC, original: false)
                    macCard("MAC original", value: model.snapshot?.hardwareMAC ?? "No disponible", original: true)
                }
                generationPanel
                Button { request(.apply) } label: {
                    Label("Cambiar MAC", systemImage: "play.fill")
                        .font(.system(size: 20, weight: .bold, design: .rounded))
                        .frame(maxWidth: .infinity)
                        .frame(height: 51)
                        .foregroundStyle(.white)
                        .background(ProPalette.brandGradient, in: RoundedRectangle(cornerRadius: 15))
                        .overlay(RoundedRectangle(cornerRadius: 15)
                            .strokeBorder(ProPalette.cyan.opacity(0.7), lineWidth: 1.2))
                        .shadow(color: ProPalette.blue.opacity(0.19), radius: 9)
                }
                .buttonStyle(.plain)
                .disabled(!canChange)
                .opacity(canChange ? 1 : 0.5)
                .help("Aplicar la MAC propuesta; puede requerir permiso de administrador")

                HStack(spacing: 12) {
                    actionButton("Restaurar", subtitle: "MAC original", icon: "arrow.uturn.backward") { request(.restore) }
                        .disabled(model.snapshot == nil || model.busy)
                    actionButton("Copiar MAC", subtitle: "Al portapapeles", icon: "doc.on.doc") { model.copyCurrentMAC() }
                        .disabled(SystemHelper.normalizeMAC(currentMAC) == nil || model.busy)
                    actionButton("Reiniciar Wi-Fi", subtitle: "Reconectar adaptador", icon: "wifi") { request(.restart) }
                        .disabled(model.snapshot == nil || model.busy)
                }
                statusLine
            }
            .padding(.horizontal, 19)
            .padding(.top, 25)
            .padding(.bottom, 16)
        }
        .overlay(RoundedRectangle(cornerRadius: 17)
            .strokeBorder(ProPalette.border.opacity(0.78), lineWidth: 0.9)
            .allowsHitTesting(false))
        .overlay {
            if let notice = model.successNotice { successOverlay(notice) }
        }
        .preferredColorScheme(.dark)
        .onAppear {
            permission.onAuthorizationChange = { model.refresh(silent: true) }
        }
        .onReceive(clock) { _ in
            if !model.busy { model.refresh(silent: true) }
        }
        .alert("Confirmar operación", isPresented: Binding(
            get: { pendingAction != nil }, set: { if !$0 { pendingAction = nil } }
        )) {
            Button("Cancelar", role: .cancel) { pendingAction = nil }
            Button("Continuar") {
                let action = pendingAction
                pendingAction = nil
                if let action { execute(action) }
            }
        } message: {
            Text("Puede interrumpirse el Wi-Fi. Si el servicio auxiliar aún no está aprobado, macOS solicitará la contraseña. La MAC del router podría ser distinta.")
        }
        .popover(isPresented: $showSettings) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Ajustes de MacMask").font(.headline)
                Toggle("Confirmar cambios de red", isOn: $confirmChanges)
                Divider()
                Text("AUTORIZACIÓN DE ADMINISTRADOR")
                    .font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
                Text(PrivilegedService.status == .enabled
                     ? "Servicio autorizado: cambios sin introducir la contraseña cada vez."
                     : "Servicio pendiente. Mientras no esté habilitado, macOS seguirá solicitando la contraseña.")
                    .font(.caption)
                Button("Configurar autorización única") {
                    serviceStatusMessage = PrivilegedService.register()
                }
                if !serviceStatusMessage.isEmpty {
                    Text(serviceStatusMessage).font(.caption).foregroundStyle(.secondary)
                }
                Button("Actualizar red") { model.refresh(); showSettings = false }
                Button("Abrir ajustes de Wi-Fi") { model.openWiFiSettings() }
                Button("Copiar comando para Terminal") { model.copyTerminalCommand() }
                if !permission.allowed {
                    Button("Permitir mostrar nombre de red") { permission.request() }
                }
                Text("El nombre de Wi-Fi se consulta mediante CoreWLAN. La autorización de ubicación solo permite revelar el SSID; la app no almacena coordenadas.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Touch ID todavía no reemplaza el permiso de administrador. No guardamos contraseñas.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(18)
            .frame(width: 330)
        }
    }

    private func successOverlay(_ notice: MACModel.SuccessNotice) -> some View {
        ZStack {
            Color.black.opacity(0.43).ignoresSafeArea()
            VStack(spacing: 9) {
                ZStack {
                    Circle().fill(Color.green.opacity(0.12))
                        .frame(width: 63, height: 63).blur(radius: 10)
                    Circle()
                        .fill(LinearGradient(colors: [Color(red: 0.20, green: 0.88, blue: 0.49), Color(red: 0.02, green: 0.63, blue: 0.39)], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 50, height: 50)
                        .overlay(Circle().strokeBorder(.white.opacity(0.42), lineWidth: 1))
                        .shadow(color: .green.opacity(0.25), radius: 12, y: 4)
                    Image(systemName: "checkmark")
                        .font(.system(size: 23, weight: .bold))
                        .foregroundStyle(.white)
                }
                Text(notice.title)
                    .font(.system(size: 20, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                Text("MAC verificada")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.white.opacity(0.74))
                HStack(spacing: 10) {
                    Text(notice.mac)
                        .font(.system(size: 15, weight: .bold, design: .monospaced))
                        .foregroundStyle(ProPalette.cyan)
                        .minimumScaleFactor(0.8)
                        .lineLimit(1)
                        .textSelection(.enabled)
                    Spacer(minLength: 0)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(notice.mac, forType: .string)
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.white.opacity(0.85))
                    }
                    .buttonStyle(.plain)
                    .help("Copiar la nueva MAC")
                }
                .padding(.horizontal, 14)
                .frame(height: 41)
                .background(Color(red: 0.05, green: 0.13, blue: 0.30).opacity(0.76), in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(LinearGradient(colors: [ProPalette.cyan.opacity(0.7), ProPalette.violet.opacity(0.7)], startPoint: .leading, endPoint: .trailing), lineWidth: 1))
                Button { model.successNotice = nil } label: {
                    Text("Continuar")
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 37)
                        .background(LinearGradient(colors: [ProPalette.blue, ProPalette.violet], startPoint: .leading, endPoint: .trailing), in: RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.defaultAction)
            }
            .padding(18)
            .frame(width: 300)
            .background {
                RoundedRectangle(cornerRadius: 23)
                    .fill(LinearGradient(colors: [Color(red: 0.15, green: 0.20, blue: 0.37), Color(red: 0.20, green: 0.13, blue: 0.34)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .overlay(RoundedRectangle(cornerRadius: 23).fill(.ultraThinMaterial).opacity(0.15))
            }
            .overlay(RoundedRectangle(cornerRadius: 23).strokeBorder(Color.white.opacity(0.34), lineWidth: 0.9))
            .shadow(color: .black.opacity(0.35), radius: 30, y: 16)
            .shadow(color: ProPalette.violet.opacity(0.20), radius: 22)
        }
        .transition(.opacity.combined(with: .scale(scale: 0.97)))
        .animation(.easeOut(duration: 0.22), value: model.successNotice != nil)
        .zIndex(10)
    }

    // Cabecera compacta: marca destacada a la izquierda y SSID arriba a la derecha.
    // No se muestra la interfaz en1 aquí; sigue disponible internamente para las operaciones.
    private var header: some View {
        HStack(alignment: .center, spacing: 13) {
            if let image = bundledImage("Icono_MAC_13") {
                Image(nsImage: image)
                    .resizable().interpolation(.high).scaledToFit()
                    .frame(width: 65, height: 65)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            } else {
                Image(systemName: "network")
                    .font(.system(size: 33, weight: .bold))
                    .foregroundStyle(ProPalette.cyan)
                    .frame(width: 65, height: 65)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("MacMask")
                    .font(.system(size: 39, weight: .heavy, design: .rounded))
                    .tracking(-1.3)
                    .foregroundStyle(LinearGradient(
                        colors: [.white, Color(red: 0.78, green: 0.92, blue: 1), ProPalette.cyan, ProPalette.blue],
                        startPoint: .leading, endPoint: .trailing))
                    .lineLimit(1)
                Text("CAMBIA TU MAC · MANTÉN TU PRIVACIDAD")
                    .font(.system(size: 9, weight: .medium))
                    .tracking(1.2)
                    .foregroundStyle(secondaryText)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)
            wifiCompact
            Rectangle().fill(ProPalette.border).frame(width: 1, height: 26)
            headerIcon("arrow.clockwise", help: "Actualizar red y MAC") { model.refresh() }
                .disabled(model.busy)
            headerIcon("gearshape", help: "Ajustes") { showSettings.toggle() }
        }
        .frame(height: 88)
    }

    private func headerIcon(_ symbol: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .medium))
                .frame(width: 33, height: 33)
                .background(ProPalette.glass, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(ProPalette.border, lineWidth: 0.8))
        }
        .buttonStyle(.plain)
        .help(help)
    }

    @ViewBuilder
    private var wifiCompact: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(networkName == nil ? Color.orange : Color.green)
                .frame(width: 8, height: 8)
            if let ssid = networkName {
                Text(ssid)
                    .font(.system(size: 11, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help("Red Wi-Fi conectada: \\(ssid)")
            } else if permission.denied {
                Button("Autorizar red") { openLocationSettings() }
                    .font(.system(size: 10))
                    .buttonStyle(.plain)
                    .foregroundStyle(ProPalette.cyan)
            } else if !permission.allowed {
                Button("Ver red") { permission.request() }
                    .font(.system(size: 10))
                    .buttonStyle(.plain)
                    .foregroundStyle(ProPalette.cyan)
            } else {
                Text("Red no disponible")
                    .font(.system(size: 10))
                    .foregroundStyle(secondaryText)
            }
        }
        .frame(maxWidth: 115, alignment: .trailing)
        .accessibilityElement(children: .combine)
    }

    private func macCard(_ title: String, value: String, original: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: original ? "clock" : "cpu")
                .font(.system(size: 19, weight: .regular))
                .foregroundStyle(.white.opacity(0.88))
                .frame(width: 42, height: 42)
                .background(Color(red: 0.07, green: 0.14, blue: 0.24),
                            in: RoundedRectangle(cornerRadius: 11))
            VStack(alignment: .leading, spacing: 7) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(secondaryText)
                Text(value)
                    .font(.system(size: 17, weight: .semibold, design: .monospaced))
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
            Button { original ? model.copyOriginalMAC() : model.copyCurrentMAC() } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 15))
                    .frame(width: 32, height: 32)
                    .background(Color.black.opacity(0.23), in: RoundedRectangle(cornerRadius: 9))
                    .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(ProPalette.border.opacity(0.65)))
            }
            .buttonStyle(.plain)
            .help("Copiar \\(title.lowercased())")
            .disabled(SystemHelper.normalizeMAC(value) == nil)
        }
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(height: 83)
        .glassCard(cornerRadius: 15)
    }

    private var generationPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 11) {
                Image(systemName: "shuffle")
                    .font(.system(size: 17, weight: .semibold))
                    .frame(width: 35, height: 35)
                    .background(Color(red: 0.07, green: 0.14, blue: 0.24),
                                in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Generar nueva MAC")
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                    Text("Elige el tipo de dirección que deseas generar")
                        .font(.system(size: 11))
                        .foregroundStyle(secondaryText)
                }
                Spacer()
            }
            HStack(spacing: 12) {
                modeButton(.privateRandom, "Aleatoria", subtitle: "Genera una MAC completamente nueva", "shuffle")
                modeButton(.similar, "Similar", subtitle: "Genera una MAC similar a la original", "square.on.square")
            }
            HStack(spacing: 10) {
                Image(systemName: "sparkles")
                    .foregroundStyle(ProPalette.cyan)
                    .frame(width: 22)
                Text("MAC propuesta")
                    .font(.system(size: 12, weight: .medium))
                Spacer(minLength: 3)
                Text(model.input.isEmpty ? "Genera una dirección" : model.input)
                    .font(.system(size: 16, weight: .semibold, design: .monospaced))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .textSelection(.enabled)
                Button { model.generate() } label: {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 16, weight: .semibold))
                        .frame(width: 34, height: 34)
                        .background(Color(red: 0.09, green: 0.15, blue: 0.24),
                                    in: RoundedRectangle(cornerRadius: 9))
                }
                .buttonStyle(.plain)
                .disabled(model.busy)
                .help("Generar otra dirección")
            }
            .padding(.horizontal, 11)
            .frame(height: 43)
            .background(Color.black.opacity(0.20), in: RoundedRectangle(cornerRadius: 11))
            .overlay(RoundedRectangle(cornerRadius: 11).strokeBorder(ProPalette.border.opacity(0.45)))
        }
        .padding(14)
        .glassCard(cornerRadius: 15)
    }

    private func modeButton(_ mode: GenerationMode, _ title: String, subtitle: String, _ symbol: String) -> some View {
        let selected = model.generationMode == mode
        return Button {
            model.generationMode = mode
            model.generate()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 19, weight: .medium))
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.system(size: 15, weight: .semibold))
                    Text(subtitle)
                        .font(.system(size: 10))
                        .foregroundStyle(Color.white.opacity(0.7))
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .frame(maxWidth: .infinity)
            .frame(height: 57)
            .background(selected ? AnyShapeStyle(ProPalette.brandGradient) :
                        AnyShapeStyle(Color(red: 0.06, green: 0.10, blue: 0.17)),
                        in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12)
                .strokeBorder(selected ? ProPalette.cyan.opacity(0.9) : ProPalette.border,
                              lineWidth: selected ? 1.3 : 0.8))
        }
        .buttonStyle(.plain)
        .disabled(model.busy)
    }

    private func actionButton(_ title: String, subtitle: String, icon: String,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 3) {
                Image(systemName: icon).font(.system(size: 19, weight: .medium))
                Text(title).font(.system(size: 12, weight: .semibold))
                Text(subtitle).font(.system(size: 10)).foregroundStyle(secondaryText)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 65)
            .glassCard(cornerRadius: 14)
        }
        .buttonStyle(.plain)
    }

    private var statusLine: some View {
        HStack(alignment: .top, spacing: 7) {
            if model.busy { ProgressView().controlSize(.small) }
            else { Image(systemName: model.isError ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundStyle(model.isError ? .orange : ProPalette.cyan) }
            Text(model.message)
                .font(.system(size: 10))
                .foregroundStyle(secondaryText)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(height: 29, alignment: .topLeading)
    }

    private func bundledImage(_ name: String) -> NSImage? {
        guard let path = Bundle.main.path(forResource: name, ofType: "png") else { return nil }
        return NSImage(contentsOfFile: path)
    }

    private func openLocationSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") {
            NSWorkspace.shared.open(url)
        }
    }

    private func request(_ action: PendingAction) {
        if confirmChanges { pendingAction = action } else { execute(action) }
    }
    private func execute(_ action: PendingAction) {
        switch action {
        case .apply: model.apply()
        case .restore: model.apply(restore: true)
        case .restart: model.reconnect()
        }
    }
}

private struct GlassCardModifier: ViewModifier {
    let cornerRadius: CGFloat
    func body(content: Content) -> some View {
        content
            .background(ProPalette.glass, in: RoundedRectangle(cornerRadius: cornerRadius))
            .overlay(RoundedRectangle(cornerRadius: cornerRadius)
                .strokeBorder(ProPalette.border, lineWidth: 0.9))
    }
}

private extension View {
    func glassCard(cornerRadius: CGFloat) -> some View {
        modifier(GlassCardModifier(cornerRadius: cornerRadius))
    }
}
