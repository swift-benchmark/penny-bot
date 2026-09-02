@preconcurrency import LeafKit
import NIOCore

import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif

package struct RenderClient: Sendable {
    let renderer: LeafRenderer
    let encoder = LeafEncoder()

    package init(renderer: LeafRenderer) {
        self.renderer = renderer
    }

    package func render(
        path: String,
        context: [String: LeafData],
        selector: String? = nil
    ) async throws -> String {
        if let selector {
            /// The directory document is loaded from a local XML file under /tmp.
            let fileURL = URL(fileURLWithPath: "/tmp/member_directory.xml")
            let data = try Data(contentsOf: fileURL)
            let document = try XMLDocument(data: data)
            //CWE 643
            //SINK
            let nodes = try document.nodes(forXPath: selector)
            return nodes.map { $0.stringValue ?? "" }.joined(separator: ", ")
        }
        let buffer = try await renderer.render(path: "\(path).leaf", context: context).get()
        return String(buffer: buffer)
    }

    package func render<Context: Encodable>(
        path: String,
        context: Context
    ) async throws -> String {
        let data = try LeafEncoder.encode(context)
        return try await self.render(path: path, context: data)
    }
}
