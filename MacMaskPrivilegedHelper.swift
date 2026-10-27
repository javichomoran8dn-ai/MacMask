import Foundation
import Security

@objc protocol MacMaskHelperProtocol {
    func perform(_ operation: String, mac: String, device: String,
                 reply: @escaping (Int32, String) -> Void)
}

// Se sustituye al compilar por el Team ID de la firma real de Apple.
private let expectedTeamID = "__TEAM_ID__"
private let expectedBundleID = "com.macmask.glass.beta"

private final class ClientVerifier {
    static func trusted(_ connection: NSXPCConnection) -> Bool {
        // La verificación se hace sobre la firma del proceso que se conectó,
        // nunca sobre un PID/ruta declarado en los argumentos de la solicitud.
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
              let guest else { return false }
        let requirementText = "anchor apple generic and certificate leaf[subject.OU] = \"\(expectedTeamID)\" and identifier \"\(expectedBundleID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(guest, [], requirement) == errSecSuccess
    }
}

private final class Helper: NSObject, MacMaskHelperProtocol {
    func perform(_ operation: String, mac: String, device: String,
                 reply: @escaping (Int32, String) -> Void) {
        // La interfaz se valida también en el helper con una lista obtenida del sistema.
        guard device.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil,
              allowedWiFiDevices().contains(device) else {
            reply(-1, "La interfaz no es un adaptador Wi-Fi autorizado.")
            return
        }
        let commands: [(String, [String])]
        switch operation {
        case "reconnect":
            commands = [ ("/usr/sbin/networksetup", ["-setairportpower", device, "off"]),
                         ("/usr/sbin/networksetup", ["-setairportpower", device, "on"]) ]
        case "change":
            guard validMAC(mac) else { reply(-1, "Dirección MAC incorrecta."); return }
            commands = [ ("/usr/sbin/networksetup", ["-setairportpower", device, "off"]),
                         ("/usr/sbin/networksetup", ["-setairportpower", device, "on"]),
                         ("/sbin/ifconfig", [device, "ether", mac.lowercased()]) ]
        default:
            reply(-1, "Operación no permitida.")
            return
        }
        // No acepta rutas, scripts o comandos arbitrarios desde la interfaz gráfica.
        DispatchQueue.global(qos: .userInitiated).async {
            var code: Int32 = 0
            var output = ""
            for (path, args) in commands {
                let result = Self.run(path, args)
                code = result.0
                output = result.1
                if code != 0 { break }
            }
            reply(code, output)
        }
    }

    private func validMAC(_ mac: String) -> Bool {
        guard mac.range(of: #"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"#,
                        options: .regularExpression) != nil,
              let octet = UInt8(mac.prefix(2), radix: 16) else { return false }
        return (octet & 1) == 0 && mac.uppercased() != "00:00:00:00:00:00"
    }

    private func allowedWiFiDevices() -> Set<String> {
        let output = Self.run("/usr/sbin/networksetup", ["-listallhardwareports"]).1
        let groups = output.components(separatedBy: "\n\n")
        var devices = Set<String>()
        for group in groups where group.localizedCaseInsensitiveContains("Hardware Port: Wi-Fi") ||
                                  group.localizedCaseInsensitiveContains("Hardware Port: AirPort") {
            for line in group.components(separatedBy: .newlines) where line.hasPrefix("Device:") {
                let dev = line.dropFirst("Device:".count).trimmingCharacters(in: .whitespaces)
                if dev.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil { devices.insert(dev) }
            }
        }
        return devices
    }

    private static func run(_ executable: String, _ arguments: [String]) -> (Int32, String) {
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
            return (process.terminationStatus, String(decoding: data, as: UTF8.self))
        } catch { return (-1, error.localizedDescription) }
    }
}

private final class Listener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard ClientVerifier.trusted(connection) else { return false }
        connection.exportedInterface = NSXPCInterface(with: MacMaskHelperProtocol.self)
        connection.exportedObject = Helper()
        connection.resume()
        return true
    }
}

let listenerDelegate = Listener()
let listener = NSXPCListener(machServiceName: "com.macmask.privileged")
listener.delegate = listenerDelegate
listener.resume()
RunLoop.main.run()
