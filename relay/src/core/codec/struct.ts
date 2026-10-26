// Tiny packed little-endian struct codec. Each struct is declared once as an
// ordered field list; offsets and size are computed from it, so the layout
// test can compare every field offset against the compiler's view of types.hpp.

type Prim = "u8" | "u16" | "u32" | "i32" | "u64" | "i64";
type Bytes = { bytes: number };
type ArrayOf = { array: Struct<any>; count: number };
type FieldType = Prim | Bytes | Struct<any> | ArrayOf;

type ValueOf<F> = F extends "u64" | "i64"
  ? bigint
  : F extends Prim
    ? number
    : F extends Bytes
      ? Uint8Array
      : F extends Struct<infer T>
        ? T
        : F extends { array: Struct<infer T> }
          ? T[]
          : never;

type Fields = readonly (readonly [string, FieldType])[];
type ObjOf<F extends Fields> = { -readonly [E in F[number] as E[0]]: ValueOf<E[1]> };

export interface Struct<T> {
  readonly name: string;
  readonly size: number;
  readonly fields: Fields;
  readonly offsets: Record<string, number>;
  decode(buf: Uint8Array, offset?: number): T;
  encode(value: T, out?: Uint8Array, offset?: number): Uint8Array;
  zero(): T;
}

const PRIM_SIZE: Record<Prim, number> = { u8: 1, u16: 2, u32: 4, i32: 4, u64: 8, i64: 8 };

const sizeOf = (t: FieldType): number =>
  typeof t === "string" ? PRIM_SIZE[t] : "bytes" in t ? t.bytes : "array" in t ? t.array.size * t.count : t.size;

function read(t: FieldType, dv: DataView, buf: Uint8Array, at: number): unknown {
  if (typeof t === "string") {
    switch (t) {
      case "u8": return dv.getUint8(at);
      case "u16": return dv.getUint16(at, true);
      case "u32": return dv.getUint32(at, true);
      case "i32": return dv.getInt32(at, true);
      case "u64": return dv.getBigUint64(at, true);
      case "i64": return dv.getBigInt64(at, true);
    }
  }
  if ("bytes" in t) return buf.slice(at, at + t.bytes);
  if ("array" in t) return Array.from({ length: t.count }, (_, i) => t.array.decode(buf, at + i * t.array.size));
  return t.decode(buf, at);
}

function write(t: FieldType, v: any, dv: DataView, buf: Uint8Array, at: number): void {
  if (typeof t === "string") {
    switch (t) {
      case "u8": return dv.setUint8(at, v);
      case "u16": return dv.setUint16(at, v, true);
      case "u32": return dv.setUint32(at, v >>> 0, true);
      case "i32": return dv.setInt32(at, v, true);
      case "u64": return dv.setBigUint64(at, BigInt.asUintN(64, v), true);
      case "i64": return dv.setBigInt64(at, BigInt.asIntN(64, v), true);
    }
  }
  if ("bytes" in t) {
    // Like C# fixed arrays: copy what fits, zero the rest.
    buf.fill(0, at, at + t.bytes);
    buf.set((v as Uint8Array).subarray(0, t.bytes), at);
    return;
  }
  if ("array" in t) {
    for (let i = 0; i < t.count; i++) t.array.encode(v[i], buf, at + i * t.array.size);
    return;
  }
  t.encode(v, buf, at);
}

function zeroOf(t: FieldType): unknown {
  if (typeof t === "string") return t === "u64" || t === "i64" ? 0n : 0;
  if ("bytes" in t) return new Uint8Array(t.bytes);
  if ("array" in t) return Array.from({ length: t.count }, () => t.array.zero());
  return t.zero();
}

export function struct<const F extends Fields>(name: string, fields: F): Struct<ObjOf<F>> {
  const offsets: Record<string, number> = {};
  let size = 0;
  for (const [n, t] of fields) {
    offsets[n] = size;
    size += sizeOf(t);
  }
  return {
    name,
    size,
    fields,
    offsets,
    decode(buf, offset = 0) {
      if (buf.length - offset < size) throw new RangeError(`${name}: need ${size} bytes, have ${buf.length - offset}`);
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const o: any = {};
      for (const [n, t] of fields) o[n] = read(t, dv, buf, offset + offsets[n]);
      return o;
    },
    encode(value, out = new Uint8Array(size), offset = 0) {
      const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
      for (const [n, t] of fields) write(t, (value as any)[n], dv, out, offset + offsets[n]);
      return out;
    },
    zero() {
      const o: any = {};
      for (const [n, t] of fields) o[n] = zeroOf(t);
      return o;
    },
  };
}

export const bytes = (n: number): Bytes => ({ bytes: n });
export const array = <T>(s: Struct<T>, count: number) => ({ array: s, count }) as const;
