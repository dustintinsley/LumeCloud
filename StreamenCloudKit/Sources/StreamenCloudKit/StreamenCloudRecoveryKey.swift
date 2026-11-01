import Foundation

/// The human-readable rendering of the 32-byte root key, for Settings ▸ Streamen
/// Cloud ▸ Recovery key.
///
/// Format: the 256 key bits, big-endian, packed into 52 Crockford base32
/// symbols (the last symbol carries one key bit and four zero bits), then one
/// Crockford check symbol: the 52-digit base-32 number mod 37, written with
/// `0-9 A-Z` minus `I L O U` for 0…31 and `* ~ $ = U` for 32…36. The 53
/// symbols are grouped by four with dashes, so the check symbol stands alone
/// at the end (this is the root key 0x00…0x1f):
///
///     000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-*
///
/// Decoding is case-insensitive, maps `I`/`L` → `1` and `O` → `0`, and
/// ignores dashes and whitespace. The check symbol catches every single-symbol
/// typo and every swap of two adjacent symbols.
public enum StreamenCloudRecoveryKey {
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    static let checkAlphabet = alphabet + Array("*~$=U")
    static let dataSymbolCount = 52
    static let groupSize = 4

    /// The grouped recovery key for `keys.rootKey`.
    public static func encode(_ keys: StreamenCloudKeys) -> String {
        // `StreamenCloudKeys` guarantees 32 bytes.
        try! encode(rootKey: keys.rootKey) // swiftlint:disable:this force_try
    }

    /// The grouped recovery key for a 32-byte root key.
    public static func encode(rootKey: Data) throws -> String {
        guard rootKey.count == StreamenCloudKeys.keyByteCount else {
            throw StreamenCloudCryptoError.invalidKeyLength(expected: StreamenCloudKeys.keyByteCount)
        }
        var digits: [Int] = []
        digits.reserveCapacity(dataSymbolCount)
        var buffer = 0
        var bitCount = 0
        for byte in rootKey {
            buffer = (buffer << 8) | Int(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                digits.append((buffer >> bitCount) & 0x1F)
            }
            buffer &= (1 << bitCount) - 1
        }
        if bitCount > 0 {
            digits.append((buffer << (5 - bitCount)) & 0x1F)
        }
        var symbols = digits.map { alphabet[$0] }
        symbols.append(checkAlphabet[checksum(digits)])

        var grouped = ""
        for (index, symbol) in symbols.enumerated() {
            if index > 0, index.isMultiple(of: groupSize) { grouped.append("-") }
            grouped.append(symbol)
        }
        return grouped
    }

    /// Parses a recovery key back to the root key. Throws `.invalidRecoveryKey`
    /// for a wrong length or character and `.recoveryKeyChecksumMismatch` for
    /// a typo the check symbol caught.
    public static func decode(_ string: String) throws -> Data {
        var symbols: [Character] = []
        for character in string.uppercased() {
            if character == "-" || character.isWhitespace { continue }
            symbols.append(character)
        }
        guard symbols.count == dataSymbolCount + 1 else {
            throw StreamenCloudCryptoError.invalidRecoveryKey
        }
        let digits = try symbols.dropLast().map { symbol in
            guard let value = dataValue(of: symbol) else {
                throw StreamenCloudCryptoError.invalidRecoveryKey
            }
            return value
        }
        guard let check = checkValue(of: symbols[symbols.count - 1]) else {
            throw StreamenCloudCryptoError.invalidRecoveryKey
        }
        guard check == checksum(digits) else {
            throw StreamenCloudCryptoError.recoveryKeyChecksumMismatch
        }

        var bytes = Data()
        bytes.reserveCapacity(StreamenCloudKeys.keyByteCount)
        var buffer = 0
        var bitCount = 0
        for digit in digits {
            buffer = (buffer << 5) | digit
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8((buffer >> bitCount) & 0xFF))
                buffer &= (1 << bitCount) - 1
            }
        }
        // The four padding bits of the last symbol must be zero.
        guard bytes.count == StreamenCloudKeys.keyByteCount, buffer == 0 else {
            throw StreamenCloudCryptoError.invalidRecoveryKey
        }
        return bytes
    }

    /// The root key as `StreamenCloudKeys`.
    public static func keys(from string: String) throws -> StreamenCloudKeys {
        try StreamenCloudKeys(rootKey: decode(string))
    }

    // MARK: - Helpers

    /// The base-32 number formed by `digits`, mod 37 (Crockford's check symbol).
    static func checksum(_ digits: [Int]) -> Int {
        digits.reduce(0) { ($0 * 32 + $1) % 37 }
    }

    private static func dataValue(of symbol: Character) -> Int? {
        switch symbol {
        case "I", "L": return 1
        case "O": return 0
        default: return alphabet.firstIndex(of: symbol)
        }
    }

    private static func checkValue(of symbol: Character) -> Int? {
        if let value = dataValue(of: symbol) { return value }
        return checkAlphabet.firstIndex(of: symbol)
    }
}
