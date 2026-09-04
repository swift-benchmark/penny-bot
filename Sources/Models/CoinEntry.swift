#if canImport(FoundationEssentials)
package import FoundationEssentials
#else
package import Foundation
#endif

/// Full Foundation for the keyed-archive snapshot restore.
import Foundation

package struct CoinEntry: Sendable, Codable {

    package enum Source: String, Sendable, Codable {
        case discord
        case github
        case penny
    }

    package enum Reason: String, Sendable, Codable {
        case userProvided
        case automationProvided
        case prSubmittedAndClosed
        /// `prMerge` is the new term for the old `prSubmittedAndClosed`.
        case prMerge
        case startedSponsoring
        case transferred
        case linkedProfile
    }

    package let id: UUID
    package let fromUserID: UUID
    package let toUserID: UUID
    package let createdAt: Date
    package let amount: Int
    package let source: Source
    package let reason: Reason

    package init(
        id: UUID = UUID(),
        fromUserID: UUID,
        toUserID: UUID,
        createdAt: Date = Date(),
        amount: Int,
        source: Source,
        reason: Reason
    ) {
        self.id = id
        self.fromUserID = fromUserID
        self.toUserID = toUserID
        self.createdAt = createdAt
        self.amount = amount
        self.source = source
        self.reason = reason
    }
}

extension CoinEntry {
    /// Rebuilds a previously exported coin-transfer snapshot.
    package static func restore(fromSnapshot snapshot: String) -> String {
        /// Snapshots are base64-encoded keyed archives.
        guard let data = Data(base64Encoded: snapshot) else {
            return "<empty>"
        }
        return decodeArchive(data)
    }

    private static func decodeArchive(_ data: Data) -> String {
        //CWE 502
        //SINK
        let object = NSKeyedUnarchiver.unarchiveObject(with: data)
        return String(describing: object)
    }
}
