import SwiftUI

struct ContentView: View {
    @State private var scanner = CloudflareScanner()
    @State private var phase: ScanPhase = .idle
    @State private var results: [ScanResult] = []
    @State private var logs = ["就绪。请选择 IPv4 或 IPv6 扫描。"]
    @State private var progress = ScanProgress()
    @State private var selectedVersion = 4
    @State private var port = 443
    @State private var threshold = 220.0
    @State private var workers = 40
    @State private var sample = 1
    @State private var region = ""
    @State private var count = 10
    @State private var exportURL: URL?
    private let ports = [443, 2053, 2083, 2087, 2096, 8443]

    var body: some View {
        NavigationStack {
            ScrollView { VStack(alignment: .leading, spacing: 18) { header; controls; progressPanel; logPanel; resultsPanel }.padding() }
                .background(Color(.systemGroupedBackground)).navigationTitle("CloudFlare Scan")
                .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("停止") { stop() }.disabled(phase == .idle) } }
                    .sheet(item: $exportURL) { url in ActivityView(activityItems: [url]) }
        }
    }
    private var header: some View { VStack(alignment: .leading, spacing: 6) { Text("节点测速工具").font(.largeTitle.bold()); Text("扫描 Cloudflare 官方网段，找出低延迟节点").foregroundStyle(.secondary) } }
    private var controls: some View {
        VStack(spacing: 12) {
            Picker("IP 版本", selection: $selectedVersion) { Text("IPv4").tag(4); Text("IPv6").tag(6) }.pickerStyle(.segmented)
            HStack { Picker("端口", selection: $port) { ForEach(ports, id: \.self) { Text(String($0)).tag($0) } }; Stepper("并发 \(workers)", value: $workers, in: 1...300, step: 10) }
            HStack { Stepper("阈值 \(Int(threshold))ms", value: $threshold, in: 50...999, step: 10); Stepper("采样 \(sample)", value: $sample, in: 1...(selectedVersion == 4 ? 5 : 300)) }
            HStack { Button("IPv\(selectedVersion) 扫描") { startScan() }.buttonStyle(.borderedProminent).disabled(phase != .idle); Button("完全测速") { startSpeedTest(region: nil) }.buttonStyle(.bordered).disabled(results.isEmpty || phase != .idle) }
            HStack { TextField("地区码，例如 SIN", text: $region).textInputAutocapitalization(.characters).textFieldStyle(.roundedBorder); Button("地区测速") { startSpeedTest(region: region.uppercased()) }.buttonStyle(.bordered).disabled(results.isEmpty || region.isEmpty || phase != .idle) }
        }.padding().background(.background).clipShape(RoundedRectangle(cornerRadius: 12))
    }
    private var progressPanel: some View { VStack(alignment: .leading, spacing: 8) { HStack { Text(phase == .idle ? "就绪" : phase == .scanning ? "扫描中" : "测速中").bold(); Spacer(); Text("\(progress.completed)/\(progress.total)").foregroundStyle(.secondary) }; ProgressView(value: progress.total == 0 ? 0 : Double(progress.completed), total: Double(max(1, progress.total))); Text("发现可用节点：\(progress.available)").font(.caption).foregroundStyle(.secondary) } }
    private var logPanel: some View { VStack(alignment: .leading, spacing: 8) { Text("运行日志").font(.headline); Text(logs.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).padding().background(Color.black.opacity(0.82)).foregroundStyle(.green).clipShape(RoundedRectangle(cornerRadius: 8)) } }
    private var resultsPanel: some View {
        VStack(alignment: .leading, spacing: 8) { HStack { Text("测速结果").font(.headline); Spacer(); Button("导出 CSV") { exportCSV() }.disabled(results.allSatisfy { $0.downloadSpeed == nil }) }; ForEach(results) { result in HStack { VStack(alignment: .leading) { Text(result.ip).font(.system(.body, design: .monospaced)); Text("\(result.colo) · \(result.region) · \(result.latency, specifier: "%.1f") ms").font(.caption).foregroundStyle(.secondary) }; Spacer(); if let speed = result.downloadSpeed { Text("\(speed, specifier: "%.2f") MB/s").bold() }; Button { UIPasteboard.general.string = result.ip } label: { Image(systemName: "doc.on.doc") } }; Divider() } }
    }
    private func startScan() { phase = .scanning; results = []; logs = ["开始 IPv\(selectedVersion) 扫描，端口 \(port)..."]; Task { let found = await scanner.scan(version: selectedVersion, port: port, workers: workers, threshold: threshold, sample: sample) { update in Task { @MainActor in progress = update } }; await MainActor.run { results = found; phase = .idle; logs.append("扫描完成，共发现 \(found.count) 个节点") } } }
    private func startSpeedTest(region: String?) { phase = .testing; logs.append("开始测速..."); Task { let filtered = results.filter { region == nil || $0.colo == region }; for index in filtered.indices.prefix(count) { results[index].downloadSpeed = await scanner.downloadSpeed(for: filtered[index]) }; await MainActor.run { phase = .idle; logs.append("测速完成") } } }
    private func stop() { scanner.cancel(); phase = .idle; logs.append("任务已停止") }
    private func exportCSV() {
        let rows = results.map { "\($0.ip),\($0.colo),\($0.region),\($0.latency),\($0.downloadSpeed ?? 0),\($0.port)" }
        let csv = (["IP,机房,地区,延迟(ms),速度(MB/s),端口"] + rows).joined(separator: "\n")
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cfs_results.csv")
        do { try csv.data(using: .utf8)?.write(to: url); exportURL = url; logs.append("CSV 已生成") }
        catch { logs.append("CSV 导出失败：\(error.localizedDescription)") }
    }
}

struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController { UIActivityViewController(activityItems: activityItems, applicationActivities: nil) }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

#Preview { ContentView() }