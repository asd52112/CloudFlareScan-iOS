import Foundation
import Network

final class CloudflareScanner {
    private let session: URLSession
    private var cancelled = false

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 3
        configuration.timeoutIntervalForResource = 4
        configuration.httpMaximumConnectionsPerHost = 100
        session = URLSession(configuration: configuration)
    }

    func cancel() { cancelled = true }

    func scan(version: Int, port: Int, workers: Int, threshold: Double, sample: Int,
              progress: @escaping (ScanProgress) -> Void) async -> [ScanResult] {
        cancelled = false
        let cidrs = await loadCIDRs(version: version)
        let addresses = generateAddresses(cidrs: cidrs, version: version, sample: sample)
        var state = ScanProgress(total: addresses.count)
        var output: [ScanResult] = []
        let limit = max(1, min(workers, 300))
        await withTaskGroup(of: ScanResult?.self) { group in
            var next = 0
            for _ in 0..<min(limit, addresses.count) {
                let address = addresses[next]
                group.addTask { [self] in await self.probe(address, port: port, version: version, threshold: threshold) }
                next += 1
            }
            while let result = await group.next() {
                if cancelled { group.cancelAll(); break }
                state.completed += 1
                if let result { output.append(result); state.available += 1 }
                state.speed = Double(state.completed) / max(0.1, Date().timeIntervalSince1970)
                progress(state)
                if next < addresses.count {
                    let address = addresses[next]
                    group.addTask { [self] in await self.probe(address, port: port, version: version, threshold: threshold) }
                    next += 1
                }
            }
        }
        return output.sorted { $0.latency < $1.latency }
    }

    func downloadSpeed(for result: ScanResult) async -> Double {
        guard !cancelled else { return 0 }
        guard let url = URL(string: "https://\(result.ip.contains(\":\") ? "[\(result.ip)]" : result.ip)/__down?bytes=50000000") else { return 0 }
        var request = URLRequest(url: url)
        request.timeoutInterval = 4
        request.setValue("speed.cloudflare.com", forHTTPHeaderField: "Host")
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        let start = Date()
        do {
            let (bytes, _) = try await session.bytes(for: request)
            var count = 0
            for try await chunk in bytes {
                count += chunk.count
                if Date().timeIntervalSince(start) >= 3 { break }
            }
            return Double(count) / 1024 / 1024 / max(0.1, Date().timeIntervalSince(start))
        } catch { return 0 }
    }

    private func probe(_ ip: String, port: Int, version: Int, threshold: Double) async -> ScanResult? {
        guard !cancelled else { return nil }
        let start = Date()
        let connection = NWConnection(host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: UInt16(port))!, using: version == 6 ? .tcp : .tcp)
        let result: Bool = await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    continuation.resume(returning: true)
                    connection.cancel()
                case .failed, .cancelled:
                    continuation.resume(returning: false)
                    connection.cancel()
                default: break
                }
            }
            connection.start(queue: .global())
        }
        guard result else { return nil }
        let latency = Date().timeIntervalSince(start) * 1000
        guard latency <= threshold else { return nil }
        let trace = await trace(for: ip, version: version)
        guard let trace else { return nil }
        return ScanResult(ip: ip, latency: latency, colo: trace.colo, region: trace.region, port: port, ipVersion: version)
    }

    private func trace(for ip: String, version: Int) async -> (colo: String, region: String)? {
        let host = ip.contains(":") ? "[\(ip)]" : ip
        guard let url = URL(string: "https://\(host)/cdn-cgi/trace") else { return nil }
        var request = URLRequest(url: url)
        request.setValue("speed.cloudflare.com", forHTTPHeaderField: "Host")
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            let values = String(decoding: data, as: UTF8.self).split(whereSeparator: { $0 == "\n" }).reduce(into: [String: String]()) { dict, line in
                let pair = line.split(separator: "=", maxSplits: 1).map(String.init)
                if pair.count == 2 { dict[pair[0]] = pair[1] }
            }
            guard let colo = values["colo"], !colo.isEmpty else { return nil }
            return (colo, values["loc"] ?? "未知地区")
        } catch { return nil }
    }

    private func loadCIDRs(version: Int) async -> [String] {
        let endpoint = version == 6 ? "https://www.cloudflare.com/ips-v6" : "https://www.cloudflare.com/ips-v4"
        guard let url = URL(string: endpoint), let (data, _) = try? await session.data(from: url) else { return [] }
        return String(decoding: data, as: UTF8.self).split(whereSeparator: { $0 == "\n" }).map(String.init)
    }

    private func generateAddresses(cidrs: [String], version: Int, sample: Int) -> [String] {
        cidrs.compactMap { cidr -> [String]? in
            let parts = cidr.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]) else { return nil }
            let count = version == 4 ? max(1, sample) : max(1, sample)
            return (0..<count).compactMap { _ -> String? in
                if version == 4 {
                    let base = cidr.split(separator: "/")[0].split(separator: ".").compactMap { UInt32($0) }
                    guard base.count == 4 else { return nil }
                    let network = (base[0] << 24) | (base[1] << 16) | (base[2] << 8) | base[3]
                    let hostBits = 32 - prefix
                    guard hostBits > 2 else { return nil }
                    let rangeSize = UInt32(1) << min(hostBits, 24)
                    let value = network | UInt32.random(in: 1..<(rangeSize - 1))
                    return "\(value >> 24 & 255).\(value >> 16 & 255).\(value >> 8 & 255).\(value & 255)"
                }
                let groups = parts[0].split(separator: ":", omittingEmptySubsequences: false).map(String.init)
                guard groups.count <= 8 else { return nil }
                let padded = Array(repeating: "0", count: 8 - groups.count) + groups
                return padded.map { group in
                    String(format: "%04x", UInt16(group, radix: 16) ?? 0)
                }.joined(separator: ":")
            }
        }.flatMap { $0 }
    }
}
