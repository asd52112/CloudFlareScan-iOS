import Foundation

struct ScanResult: Identifiable, Hashable {
    let id = UUID()
    let ip: String
    let latency: Double
    let colo: String
    let region: String
    let port: Int
    let ipVersion: Int
    var downloadSpeed: Double?
}

enum ScanPhase: Equatable {
    case idle
    case scanning
    case testing
}

struct ScanProgress {
    var completed = 0
    var total = 0
    var available = 0
    var speed = 0.0
}
