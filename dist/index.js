import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
var Otp;
(function (Otp) {
    let HashAlgorithm;
    (function (HashAlgorithm) {
        HashAlgorithm["SHA1"] = "sha1";
        HashAlgorithm["SHA256"] = "sha256";
        HashAlgorithm["SHA384"] = "sha384";
        HashAlgorithm["SHA512"] = "sha512";
    })(HashAlgorithm = Otp.HashAlgorithm || (Otp.HashAlgorithm = {}));
    class Hotp {
        static generate(secret, counter, options) {
            const opts = Object.assign(Object.assign({}, this.DEFAULTS), options);
            const bytes = Buffer.alloc(8);
            bytes.writeBigUInt64BE(BigInt(counter));
            const hmac = createHmac(opts.algorithm, secret);
            hmac.update(bytes);
            const hash = hmac.digest();
            const offset = hash[hash.length - 1] & 0xf;
            const token = ((hash[offset] & 0x7f) << 24 >>> 0)
                | hash[offset + 1] << 16
                | hash[offset + 2] << 8
                | hash[offset + 3];
            return (token % (Math.pow(10, opts.digits))).toString().padStart(opts.digits, '0');
        }
        static validate(token, secret, counter, window = 0, options) {
            const opts = Object.assign(Object.assign({}, this.DEFAULTS), options);
            if (token.length !== opts.digits)
                return false;
            const compare = (counter) => {
                const generated = Hotp.generate(secret, counter, opts);
                const token_buffer = Buffer.from(token);
                const generated_buffer = Buffer.from(generated);
                if (token_buffer.length !== generated_buffer.length)
                    return false;
                return timingSafeEqual(token_buffer, generated_buffer);
            };
            if (compare(counter))
                return true;
            for (let i = 1; i <= window; i++) {
                if (compare(counter + i))
                    return true;
                if (compare(counter - i))
                    return true;
            }
            return false;
        }
    }
    Hotp.DEFAULTS = {
        algorithm: HashAlgorithm.SHA1,
        digits: 6,
    };
    Otp.Hotp = Hotp;
    class Totp {
        static generate(secret, time = Date.now(), options) {
            const opts = Object.assign(Object.assign({}, this.DEFAULTS), options);
            const counter = Totp.timeToCounter(time, opts.period);
            return Hotp.generate(secret, counter, opts);
        }
        static validate(token, secret, time = Date.now(), window = 1, options) {
            const opts = Object.assign(Object.assign({}, this.DEFAULTS), options);
            const counter = Totp.timeToCounter(time, opts.period);
            return Hotp.validate(token, secret, counter, window, opts);
        }
        static remaining(period = 30, time = Date.now()) {
            return period - (time / 1000) % period;
        }
        static timeToCounter(time, period) {
            return Math.floor((time / 1000) / period);
        }
    }
    Totp.DEFAULTS = {
        algorithm: HashAlgorithm.SHA1,
        digits: 6,
        period: 30,
    };
    Otp.Totp = Totp;
    class Base32 {
        static encode(buffer) {
            let bits = 0;
            let value = 0;
            let output = '';
            for (let i = 0; i < buffer.length; i++) {
                value = (value << 8) | buffer[i];
                bits += 8;
                while (bits >= 5) {
                    output += this.ALPHABET[(value >>> (bits - 5)) & 31];
                    bits -= 5;
                }
            }
            if (bits > 0) {
                output += this.ALPHABET[(value << (5 - bits)) & 31];
            }
            return output;
        }
        static decode(str) {
            const cleaned = str.toUpperCase().trim().replace(/=+$/, '');
            if (/[^A-Z2-7]/.test(cleaned))
                throw new Error(`Invalid Base32 character in: "${str}"`);
            const buffer = Buffer.alloc(Math.floor((cleaned.length * 5) / 8));
            let bits = 0;
            let value = 0;
            let index = 0;
            for (let i = 0; i < cleaned.length; i++) {
                const val = this.ALPHABET.indexOf(cleaned[i]);
                value = (value << 5) | val;
                bits += 5;
                if (bits >= 8) {
                    buffer[index++] = (value >>> (bits - 8)) & 255;
                    bits -= 8;
                }
            }
            return buffer;
        }
    }
    Base32.ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    Otp.Base32 = Base32;
    class Url {
        static getHotpUrl(issuer, label, secret, counter, options) {
            const opts = Object.assign(Object.assign({}, Hotp.DEFAULTS), options);
            const url = new URL(`otpauth://hotp/${issuer}:${label}`);
            url.searchParams.set('secret', Base32.encode(secret));
            url.searchParams.set('algorithm', opts.algorithm.toUpperCase());
            url.searchParams.set('digits', opts.digits.toString());
            url.searchParams.set('counter', counter.toString());
            url.searchParams.set('issuer', issuer);
            return url.toString();
        }
        static getTotpUrl(issuer, label, secret, options) {
            const opts = Object.assign(Object.assign({}, Totp.DEFAULTS), options);
            const url = new URL(`otpauth://totp/${issuer}:${label}`);
            url.searchParams.set('secret', Base32.encode(secret));
            url.searchParams.set('algorithm', opts.algorithm.toUpperCase());
            url.searchParams.set('digits', opts.digits.toString());
            url.searchParams.set('period', opts.period.toString());
            url.searchParams.set('issuer', issuer);
            return url.toString();
        }
    }
    Otp.Url = Url;
})(Otp || (Otp = {}));
export default Otp;
//# sourceMappingURL=index.js.map