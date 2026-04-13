import { createHmac, timingSafeEqual } from 'node:crypto'
import { Buffer } from 'node:buffer'

namespace Otp {
    export enum HashAlgorithm {
        SHA1 = 'sha1',
        SHA256 = 'sha256',
        SHA384 = 'sha384',
        SHA512 = 'sha512',
    }

    export type HotpOptions = {
        algorithm: HashAlgorithm
        digits: number
    }

    export type TotpOptions = {
        algorithm: HashAlgorithm
        digits: number
        period: number
    }

    export class Hotp {
        static readonly DEFAULTS: HotpOptions = {
            algorithm: HashAlgorithm.SHA1,
            digits: 6,
        }

        static generate(secret: Buffer, counter: number, options?: Partial<HotpOptions>): string {
            const opts = { ...this.DEFAULTS, ...options }
            const bytes = Buffer.alloc(8)
            bytes.writeBigUInt64BE(BigInt(counter))

            const hmac = createHmac(opts.algorithm, secret)
            hmac.update(bytes)
            const hash = hmac.digest()

            const offset = hash[hash.length - 1] & 0xf
            const token = ((hash[offset] & 0x7f) << 24 >>> 0)
                | hash[offset + 1] << 16
                | hash[offset + 2] << 8
                | hash[offset + 3]

            return (token % (10 ** opts.digits)).toString().padStart(opts.digits, '0')
        }

        static validate(token: string, secret: Buffer, counter: number, window: number = 0, options?: Partial<HotpOptions>): boolean {
            const opts = { ...this.DEFAULTS, ...options }
            if (token.length !== opts.digits) return false
            const compare = (counter: number) => {
                const generated = Hotp.generate(secret, counter, opts)
                const token_buffer = Buffer.from(token)
                const generated_buffer = Buffer.from(generated)
                if (token_buffer.length !== generated_buffer.length) return false
                return timingSafeEqual(token_buffer, generated_buffer)
            }
            if (compare(counter)) return true
            for (let i = 1; i <= window; i++) {
                if (compare(counter + i)) return true
                if (compare(counter - i)) return true
            }
            return false
        }
    }

    export class Totp {
        static readonly DEFAULTS: TotpOptions = {
            algorithm: HashAlgorithm.SHA1,
            digits: 6,
            period: 30,
        }

        static generate(secret: Buffer, time: number = Date.now(), options?: Partial<TotpOptions>): string {
            const opts = { ...this.DEFAULTS, ...options }
            const counter = Totp.timeToCounter(time, opts.period)
            return Hotp.generate(secret, counter, opts)
        }

        static validate(token: string, secret: Buffer, time: number = Date.now(), window: number = 1, options?: Partial<TotpOptions>): boolean {
            const opts = { ...this.DEFAULTS, ...options }
            const counter = Totp.timeToCounter(time, opts.period)
            return Hotp.validate(token, secret, counter, window, opts)
        }

        static remaining(period: number = 30, time: number = Date.now()): number {
            return period - (time / 1000) % period
        }

        static timeToCounter(time: number, period: number): number {
            return Math.floor((time / 1000) / period)
        }
    }

    export class Base32 {
        private static readonly ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

        public static encode(buffer: Buffer): string {
            let bits = 0
            let value = 0
            let output = ''

            for (let i = 0; i < buffer.length; i++) {
                value = (value << 8) | buffer[i]
                bits += 8

                while (bits >= 5) {
                    output += this.ALPHABET[(value >>> (bits - 5)) & 31]
                    bits -= 5
                }
            }

            if (bits > 0) {
                output += this.ALPHABET[(value << (5 - bits)) & 31]
            }

            return output
        }

        public static decode(str: string): Buffer {
            const cleaned = str.toUpperCase().trim().replace(/=+$/, '')
            if (/[^A-Z2-7]/.test(cleaned)) throw new Error(`Invalid Base32 character in: "${str}"`)

            const buffer = Buffer.alloc(Math.floor((cleaned.length * 5) / 8))

            let bits = 0
            let value = 0
            let index = 0

            for (let i = 0; i < cleaned.length; i++) {
                const val = this.ALPHABET.indexOf(cleaned[i])

                value = (value << 5) | val
                bits += 5

                if (bits >= 8) {
                    buffer[index++] = (value >>> (bits - 8)) & 255
                    bits -= 8
                }
            }

            return buffer
        }
    }

    export class Url {
        public static getHotpUrl(issuer: string, label: string, secret: Buffer, counter: number, options?: Partial<HotpOptions>): string {
            const opts = { ...Hotp.DEFAULTS, ...options }
            const url = new URL(`otpauth://hotp/${issuer}:${label}`)
            url.searchParams.set('secret', Base32.encode(secret))
            url.searchParams.set('algorithm', opts.algorithm.toUpperCase())
            url.searchParams.set('digits', opts.digits.toString())
            url.searchParams.set('counter', counter.toString())
            url.searchParams.set('issuer', issuer)
            return url.toString()
        }

        public static getTotpUrl(issuer: string, label: string, secret: Buffer, options?: Partial<TotpOptions>): string {
            const opts = { ...Totp.DEFAULTS, ...options }
            const url = new URL(`otpauth://totp/${issuer}:${label}`)
            url.searchParams.set('secret', Base32.encode(secret))
            url.searchParams.set('algorithm', opts.algorithm.toUpperCase())
            url.searchParams.set('digits', opts.digits.toString())
            url.searchParams.set('period', opts.period.toString())
            url.searchParams.set('issuer', issuer)
            return url.toString()
        }
    }
}

export default Otp