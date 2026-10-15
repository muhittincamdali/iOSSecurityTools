import Foundation

// The generators hold a secret. Their descriptions and mirrors leave it out, so `print`, string
// interpolation, `dump` and the debugger's summary cannot write it to a log.

extension HOTP: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "HOTP(\(algorithm.rawValue), \(digits) digits)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["algorithm": algorithm, "digits": digits], displayStyle: .struct)
    }
}

extension TOTP: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "TOTP(\(algorithm.rawValue), \(digits) digits, \(period) s)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["algorithm": algorithm, "digits": digits, "period": period], displayStyle: .struct)
    }
}

extension OTPAuthURI: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        let generator = switch kind {
        case .totp(let totp): totp.description
        case .hotp(let hotp, let counter): "\(hotp.description), counter \(counter)"
        }
        return "OTPAuthURI(\(issuer.map { "\($0): " } ?? "")\(account), \(generator))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["kind": kind, "account": account, "issuer": issuer as Any], displayStyle: .struct)
    }
}
