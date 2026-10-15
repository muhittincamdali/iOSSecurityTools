import Foundation

/// A value that prints as `<redacted>`.
///
/// Wrap passwords, tokens and personal data so that `print`, string interpolation, `dump`,
/// `Mirror`, `NSLog("%@")` and the debugger summary never show them. The value is still there;
/// read it explicitly with ``wrappedValue``.
///
/// ```swift
/// struct LoginRequest: Codable {
///     var username: String
///     @Redacted var password: String
/// }
///
/// let request = LoginRequest(username: "alice", password: "hunter2")
/// print(request)   // LoginRequest(username: "alice", _password: <redacted>)
/// ```
///
/// `Codable` is transparent: a `Redacted<String>` encodes as the plain string, because encoding a
/// request body is a deliberate use of the value. Logging that JSON would show it again.
@propertyWrapper
public struct Redacted<Value> {
    /// The text every description of the value shows.
    public static var placeholder: String { "<redacted>" }

    /// The wrapped value. Reading it is the only way to see it.
    public var wrappedValue: Value

    /// Wraps a value.
    public init(wrappedValue: Value) {
        self.wrappedValue = wrappedValue
    }

    /// Wraps a value.
    public init(_ value: Value) {
        self.wrappedValue = value
    }
}

extension Redacted: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { Self.placeholder }
    public var debugDescription: String { Self.placeholder }
    /// A mirror without children, so `dump` and reflection-based loggers see nothing inside.
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: nil) }
}

extension Redacted: CustomLeafReflectable {}

extension Redacted: Sendable where Value: Sendable {}

extension Redacted: Equatable where Value: Equatable {}

extension Redacted: Hashable where Value: Hashable {}

extension Redacted: Decodable where Value: Decodable {
    public init(from decoder: any Decoder) throws {
        wrappedValue = try decoder.singleValueContainer().decode(Value.self)
    }
}

extension Redacted: Encodable where Value: Encodable {
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wrappedValue)
    }
}
