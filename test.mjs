import test from 'node:test'
import assert from 'node:assert'

import Otp from './dist/index.js'

const rfc = {
    hotp: [
        // "RFC 4226 - Appendix D - HOTP Algorithm: Test Values"
        // https://datatracker.ietf.org/doc/html/rfc4226
        { secret: '12345678901234567890', count: 0, expected: '755224', },
        { secret: '12345678901234567890', count: 1, expected: '287082', },
        { secret: '12345678901234567890', count: 2, expected: '359152', },
        { secret: '12345678901234567890', count: 3, expected: '969429', },
        { secret: '12345678901234567890', count: 4, expected: '338314', },
        { secret: '12345678901234567890', count: 5, expected: '254676', },
        { secret: '12345678901234567890', count: 6, expected: '287922', },
        { secret: '12345678901234567890', count: 7, expected: '162583', },
        { secret: '12345678901234567890', count: 8, expected: '399871', },
        { secret: '12345678901234567890', count: 9, expected: '520489', },
    ],
    totp: [
        // "RFC 6238 - Appendix B - Test Vectors"
        // https://datatracker.ietf.org/doc/html/rfc6238
        { time: 59, expected: '94287082', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 59, expected: '46119246', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 59, expected: '90693936', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
        { time: 1111111109, expected: '07081804', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 1111111109, expected: '68084774', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 1111111109, expected: '25091201', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
        { time: 1111111111, expected: '14050471', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 1111111111, expected: '67062674', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 1111111111, expected: '99943326', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
        { time: 1234567890, expected: '89005924', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 1234567890, expected: '91819424', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 1234567890, expected: '93441116', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
        { time: 2000000000, expected: '69279037', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 2000000000, expected: '90698825', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 2000000000, expected: '38618901', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
        { time: 20000000000, expected: '65353130', algorithm: Otp.HashAlgorithm.SHA1, secret: '12345678901234567890', },
        { time: 20000000000, expected: '77737706', algorithm: Otp.HashAlgorithm.SHA256, secret: '12345678901234567890123456789012', },
        { time: 20000000000, expected: '47863826', algorithm: Otp.HashAlgorithm.SHA512, secret: '1234567890123456789012345678901234567890123456789012345678901234', },
    ],
}

test('hotp rfc4226 test values', () => {
    for (const value of rfc.hotp) {
        test(`test value count ${value.count}`, () => {
            const key = Buffer.from(value.secret, 'utf8')
            const actual = Otp.Hotp.generate(key, value.count)

            assert.strictEqual(value.expected, actual)
        })
    }
})

test('totp rfc6238 test values', () => {
    for (const value of rfc.totp) {
        test(`test value, time: ${value.time}, algorithm: ${value.algorithm}`, () => {
            const key = Buffer.from(value.secret, 'utf8')
            const time = value.time * 1000 // test values are given in seconds, but we expect milliseconds
            const actual = Otp.Totp.generate(key, time, { algorithm: value.algorithm, digits: value.expected.length })

            assert.strictEqual(value.expected, actual)
        })
    }
})