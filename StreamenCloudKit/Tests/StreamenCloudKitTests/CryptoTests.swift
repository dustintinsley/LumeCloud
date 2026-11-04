import CryptoKit
import Foundation
@testable import StreamenCloudKit
import Testing

/// Known answers computed independently (Python `cryptography` + `hmac`), not
/// by this Kit, plus the RFC test vectors of the primitives underneath.
@Suite("Keys & envelope")
struct CryptoTests {
    static let rootKey = Data(0 ..< 32)
    static let profileKey = "profile/6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"

    private static func hex(_ string: String) -> Data {
        var data = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            data.append(UInt8(string[index ..< next], radix: 16)!)
            index = next
        }
        return data
    }

    // MARK: Primitives

    @Test func hkdfMatchesRFC5869TestCase3() {
        // RFC 5869 A.3: SHA-256, zero-length salt and info.
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(repeating: 0x0B, count: 22)),
            salt: Data(),
            info: Data(),
            outputByteCount: 42
        ).withUnsafeBytes { Data($0) }
        #expect(okm == Self.hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))
    }

    @Test func hmacMatchesRFC4231TestCase2() {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data("what do ya want for nothing?".utf8),
            using: SymmetricKey(data: Data("Jefe".utf8))
        )
        #expect(Data(mac) == Self.hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
    }

    // MARK: Derivation (§2.1–2.3)

    @Test func derivedKeysMatchKnownAnswers() throws {
        let keys = try StreamenCloudKeys(rootKey: Self.rootKey)
        #expect(Base64URL.encode(keys.encKey) == "LhmApjcFPwtajnNBmJHXCsqPXAY2F8F6uPhsuuhcPbE")
        #expect(Base64URL.encode(keys.idKey) == "o1HfnMeZVKFXqkwYO2npG23sCLLOdkmTiYjXx7zRXRg")
        #expect(Base64URL.encode(keys.authKey) == "sPYR8-X019Rn_JD_XQCJmO93EUtyPAwJSvDIZqefJbo")
        #expect(keys.authToken == "sPYR8-X019Rn_JD_XQCJmO93EUtyPAwJSvDIZqefJbo")
        #expect(keys.authVerifier == "9epJHjdeu5JKPc154YcAM_AusFank91SmEGm5ektmtE")
    }

    @Test func accountIDMatchesKnownAnswer() throws {
        // HKDF-SHA256(rootKey, salt = empty, info = "streamen-cloud/v1/account", L = 16), via Python hmac.
        let keys = try StreamenCloudKeys(rootKey: Self.rootKey)
        #expect(keys.accountId == "3Z_WPSEMqpMTD12R-NZkYw")
        #expect(keys.accountId.count == 22)
        #expect(try StreamenCloudKeys(rootKey: Data(repeating: 0xFF, count: 32)).accountId != keys.accountId)
    }

    @Test func recordIDsMatchKnownAnswers() throws {
        let keys = try StreamenCloudKeys(rootKey: Self.rootKey)
        let rid = keys.recordID(for: Self.profileKey)
        #expect(rid == "FgIGlleBtESMoREoxhCVanXgz55Xd_oyjEEK38mWchY")
        #expect(rid.count == 43)
        #expect(keys.recordID(for: "content/6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D/movie-1001")
            == "V9Zweas_CUerA0Ftbo31DDk1xzwCcsSUoAqOqBpnotw")
    }

    @Test func rootKeyLengthIsChecked() {
        #expect(throws: StreamenCloudCryptoError.invalidKeyLength(expected: 32)) {
            try StreamenCloudKeys(rootKey: Data(count: 31))
        }
        #expect(throws: StreamenCloudCryptoError.invalidKeyLength(expected: 32)) {
            try StreamenCloudKeys(rootKey: Data(count: 33))
        }
    }

    @Test func generatedKeysAreFreshAndRoundTrip() throws {
        let a = StreamenCloudKeys.generate()
        let b = StreamenCloudKeys.generate()
        #expect(a.rootKey.count == 32)
        #expect(a.rootKey != b.rootKey)
        #expect(try StreamenCloudKeys(rootKey: a.rootKey) == a)
    }

    @Test func keysNeverPrintSecrets() throws {
        let keys = try StreamenCloudKeys(rootKey: Self.rootKey)
        var dumped = ""
        dump(keys, to: &dumped)
        for text in ["\(keys)", String(reflecting: keys), dumped] {
            #expect(!text.contains(keys.authToken))
            #expect(!text.contains(Base64URL.encode(keys.rootKey)))
            #expect(!text.contains("bytes"))
        }
    }

    // MARK: Envelope (§2.4)

    @Test func envelopeMatchesKnownAnswer() throws {
        let keys = try StreamenCloudKeys(rootKey: Self.rootKey)
        let rid = keys.recordID(for: Self.profileKey)
        let payload = #"{"data":{"colorRaw":"blue","createdAt":1760000000000,"id":"6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D","isChild":true,"name":"Zoë's \"Room\"","sortOrder":1,"symbolName":"star.fill","updatedAt":1760000123456},"key":"profile/6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D","type":"profile","v":1}"#
        let wire = try keys.seal(Data(payload.utf8), rid: rid, nonce: Data(0xA0 ..< 0xAC))
        #expect(wire == "AaChoqOkpaanqKmqq_AviP0fAgXnBo1vrKDPwbHPv0VphapxV80ITd8wLtBhOYvtAGYCYkRgWf5yYY7zQkGUJ3TSQM-V1coXgIFlFa4gN2hPO2vDC9Me3UzME8R_MkOnBJ79fKfEOn0yCLkDy8SFLS2K4GcZP_tQSvLuvqgg7s9GsLlVqWkXRnVmgrwTxlz5xoBtPFvjyjM8IZQ4xnuWVG3kSYFFIJMyWBZYM-CQC8zs03pxZgVHuMa_Et1P6UEUigmGv0Q44fw2Jd2hXeSZYMbq-mciH8jhp02eFm563LehBUSzwWNkYLvtg2bAwx3vanqsKPx8soLhtgeWlfXxGcJc_IHMkK4gN0wPtlNTixgbLOdYr6JTRX2FkW8FIx_lsNdm0GUe_UpcBIPl2NKsMuZj2nU")
        #expect(try keys.open(wire, rid: rid) == Data(payload.utf8))
    }

    @Test func envelopeLayout() throws {
        let keys = StreamenCloudKeys.generate()
        let wire = try keys.seal(Data("hello".utf8), rid: "r")
        let envelope = try #require(Base64URL.decode(wire))
        #expect(envelope.first == 0x01)
        #expect(envelope.count == 1 + 12 + 5 + 16)
        #expect(!wire.contains("=") && !wire.contains("+") && !wire.contains("/"))
    }

    @Test func envelopeRoundTripUsesFreshNonces() throws {
        let keys = StreamenCloudKeys.generate()
        let plaintext = Data("{\"v\":1}".utf8)
        let first = try keys.seal(plaintext, rid: "rid-a")
        let second = try keys.seal(plaintext, rid: "rid-a")
        #expect(first != second)
        #expect(try keys.open(first, rid: "rid-a") == plaintext)
        #expect(try keys.open(second, rid: "rid-a") == plaintext)
        #expect(try keys.open(keys.seal(Data(), rid: "rid-a"), rid: "rid-a") == Data())
    }

    @Test func wrongRIDFailsToOpen() throws {
        let keys = StreamenCloudKeys.generate()
        let wire = try keys.seal(Data("secret".utf8), rid: "rid-a")
        #expect(throws: StreamenCloudCryptoError.authenticationFailed) { try keys.open(wire, rid: "rid-b") }
    }

    @Test func wrongKeyFailsToOpen() throws {
        let wire = try StreamenCloudKeys.generate().seal(Data("secret".utf8), rid: "rid-a")
        #expect(throws: StreamenCloudCryptoError.authenticationFailed) {
            try StreamenCloudKeys.generate().open(wire, rid: "rid-a")
        }
    }

    @Test func tamperedEnvelopeFailsToOpen() throws {
        let keys = StreamenCloudKeys.generate()
        let envelope = try #require(Base64URL.decode(keys.seal(Data("secret payload".utf8), rid: "r")))
        // Flip one bit in the nonce, the ciphertext and the tag in turn.
        for index in [1, 14, envelope.count - 1] {
            var tampered = envelope
            tampered[index] ^= 0x01
            #expect(throws: StreamenCloudCryptoError.authenticationFailed) {
                try keys.open(Base64URL.encode(tampered), rid: "r")
            }
        }
        // Truncated.
        #expect(throws: StreamenCloudCryptoError.authenticationFailed) {
            try keys.open(Base64URL.encode(envelope.dropLast()), rid: "r")
        }
    }

    @Test func unknownVersionIsTyped() throws {
        let keys = StreamenCloudKeys.generate()
        var envelope = try #require(Base64URL.decode(keys.seal(Data("x".utf8), rid: "r")))
        envelope[0] = 0x02
        #expect(throws: StreamenCloudCryptoError.unsupportedEnvelopeVersion(2)) {
            try keys.open(Base64URL.encode(envelope), rid: "r")
        }
        // Checked before the length, so a future short format still reads as "unknown version".
        #expect(throws: StreamenCloudCryptoError.unsupportedEnvelopeVersion(0x7F)) {
            try keys.open(Base64URL.encode(Data([0x7F])), rid: "r")
        }
    }

    @Test func garbageIsRejected() {
        let keys = StreamenCloudKeys.generate()
        #expect(throws: StreamenCloudCryptoError.invalidBase64) { try keys.open("not base64!", rid: "r") }
        #expect(throws: StreamenCloudCryptoError.malformedEnvelope) { try keys.open("", rid: "r") }
        #expect(throws: StreamenCloudCryptoError.malformedEnvelope) {
            try keys.open(Base64URL.encode(Data([0x01, 0, 0])), rid: "r")
        }
    }

    @Test func nonceLengthIsChecked() {
        let keys = StreamenCloudKeys.generate()
        #expect(throws: StreamenCloudCryptoError.invalidKeyLength(expected: 12)) {
            try keys.seal(Data(), rid: "r", nonce: Data(count: 8))
        }
    }

    // MARK: Base64url

    @Test func base64URLIsUnpaddedAndStrict() {
        #expect(Base64URL.encode(Data([0xFB, 0xFF])) == "-_8")
        #expect(Base64URL.encode(Data()) == "")
        #expect(Base64URL.decode("-_8") == Data([0xFB, 0xFF]))
        #expect(Base64URL.decode("+/8") == nil)
        #expect(Base64URL.decode("-_8=") == nil)
        #expect(Base64URL.decode("A") == nil)
        #expect(Base64URL.decode("") == Data())
        for length in 0 ..< 40 {
            let data = Data((0 ..< length).map { UInt8(truncatingIfNeeded: $0 &* 37) })
            #expect(Base64URL.decode(Base64URL.encode(data)) == data)
        }
    }
}
