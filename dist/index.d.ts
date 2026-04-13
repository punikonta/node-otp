import { Buffer } from 'node:buffer';
declare namespace Otp {
    enum HashAlgorithm {
        SHA1 = "sha1",
        SHA256 = "sha256",
        SHA384 = "sha384",
        SHA512 = "sha512"
    }
    type HotpOptions = {
        algorithm: HashAlgorithm;
        digits: number;
    };
    type TotpOptions = {
        algorithm: HashAlgorithm;
        digits: number;
        period: number;
    };
    class Hotp {
        static readonly DEFAULTS: HotpOptions;
        static generate(secret: Buffer, counter: number, options?: Partial<HotpOptions>): string;
        static validate(token: string, secret: Buffer, counter: number, window?: number, options?: Partial<HotpOptions>): boolean;
    }
    class Totp {
        static readonly DEFAULTS: TotpOptions;
        static generate(secret: Buffer, time?: number, options?: Partial<TotpOptions>): string;
        static validate(token: string, secret: Buffer, time?: number, window?: number, options?: Partial<TotpOptions>): boolean;
        static remaining(period?: number, time?: number): number;
        static timeToCounter(time: number, period: number): number;
    }
    class Base32 {
        private static readonly ALPHABET;
        static encode(buffer: Buffer): string;
        static decode(str: string): Buffer;
    }
    class Url {
        static getHotpUrl(issuer: string, label: string, secret: Buffer, counter: number, options?: Partial<HotpOptions>): string;
        static getTotpUrl(issuer: string, label: string, secret: Buffer, options?: Partial<TotpOptions>): string;
    }
}
export default Otp;
