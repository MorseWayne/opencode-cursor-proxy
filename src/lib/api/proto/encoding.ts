/**
 * Protobuf Encoding Helpers
 *
 * Low-level utilities for encoding protobuf wire format:
 * - Varint encoding (wire type 0)
 * - Length-delimited encoding (wire type 2)
 * - Fixed-width encoding (wire types 1, 5)
 * - google.protobuf.Value encoding for dynamic JSON-like data
 */

// --- Basic Varint and Field Encoding ---

/**
 * Encode a varint (variable-length integer) for protobuf
 * Supports both number and bigint for large values
 */
export function encodeVarint(value: number | bigint): Uint8Array {
  const bytes: number[] = [];
  let v = BigInt(value);
  while (v > 127n) {
    bytes.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  bytes.push(Number(v));
  return new Uint8Array(bytes);
}

/**
 * Encode a string field in protobuf format
 * Field format: (field_number << 3) | wire_type
 * String wire type = 2 (length-delimited)
 */
export function encodeStringField(fieldNumber: number, value: string): Uint8Array {
  if (!value) return new Uint8Array(0);

  const fieldTag = (fieldNumber << 3) | 2; // wire type 2 = length-delimited
  const encoded = new TextEncoder().encode(value);
  const length = encodeVarint(encoded.length);

  const result = new Uint8Array(1 + length.length + encoded.length);
  result[0] = fieldTag;
  result.set(length, 1);
  result.set(encoded, 1 + length.length);

  return result;
}

/**
 * Encode a uint32 field (varint, wire type 0)
 */
export function encodeUint32Field(fieldNumber: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0);

  const fieldTag = (fieldNumber << 3) | 0; // wire type 0 = varint
  const encoded = encodeVarint(value);

  const result = new Uint8Array(1 + encoded.length);
  result[0] = fieldTag;
  result.set(encoded, 1);

  return result;
}

/**
 * Encode an int32 field (varint, wire type 0)
 */
export function encodeInt32Field(fieldNumber: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0);

  const fieldTag = (fieldNumber << 3) | 0; // wire type 0 = varint
  const encoded = encodeVarint(value);

  const result = new Uint8Array(1 + encoded.length);
  result[0] = fieldTag;
  result.set(encoded, 1);

  return result;
}

/**
 * Encode an int64 field (varint, wire type 0)
 */
export function encodeInt64Field(fieldNumber: number, value: bigint): Uint8Array {
  const fieldTag = (fieldNumber << 3) | 0; // wire type 0 = varint
  const encoded = encodeVarint(value);

  const result = new Uint8Array(1 + encoded.length);
  result[0] = fieldTag;
  result.set(encoded, 1);

  return result;
}

/**
 * Encode a nested message field (length-delimited, wire type 2)
 */
export function encodeMessageField(fieldNumber: number, data: Uint8Array): Uint8Array {
  const fieldTag = (fieldNumber << 3) | 2; // wire type 2 = length-delimited
  const length = encodeVarint(data.length);

  const result = new Uint8Array(1 + length.length + data.length);
  result[0] = fieldTag;
  result.set(length, 1);
  result.set(data, 1 + length.length);

  return result;
}

/**
 * Encode a bool field (varint, wire type 0)
 */
export function encodeBoolField(fieldNumber: number, value: boolean): Uint8Array {
  const fieldTag = (fieldNumber << 3) | 0; // wire type 0 = varint
  return new Uint8Array([fieldTag, value ? 1 : 0]);
}

/**
 * Encode a double field (64-bit, wire type 1)
 */
export function encodeDoubleField(fieldNumber: number, value: number): Uint8Array {
  const fieldTag = (fieldNumber << 3) | 1; // wire type 1 = 64-bit
  const buffer = new ArrayBuffer(9);
  const view = new DataView(buffer);
  view.setUint8(0, fieldTag);
  view.setFloat64(1, value, true); // little-endian
  return new Uint8Array(buffer);
}

/**
 * Concatenate multiple Uint8Arrays into one
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// --- google.protobuf.Value Encoding ---

/**
 * Encode a JavaScript value as google.protobuf.Value
 *
 * google.protobuf.Value oneof:
 *   field 1: null_value (enum NullValue)
 *   field 2: number_value (double)
 *   field 3: string_value (string)
 *   field 4: bool_value (bool)
 *   field 5: struct_value (Struct)
 *   field 6: list_value (ListValue)
 */
export function encodeProtobufValue(value: unknown): Uint8Array {
  if (value === null || value === undefined) {
    // NullValue enum = 0
    return encodeUint32Field(1, 0);
  }

  if (typeof value === "number") {
    return encodeDoubleField(2, value);
  }

  if (typeof value === "string") {
    return encodeStringField(3, value);
  }

  if (typeof value === "boolean") {
    return encodeBoolField(4, value);
  }

  if (Array.isArray(value)) {
    // ListValue: field 1 = repeated Value
    const listBytes: Uint8Array[] = [];
    for (const item of value) {
      const itemValue = encodeProtobufValue(item);
      listBytes.push(encodeMessageField(1, itemValue));
    }
    const listValue = concatBytes(...listBytes);
    return encodeMessageField(6, listValue);
  }

  if (typeof value === "object") {
    // Struct: field 1 = map<string, Value> (encoded as repeated MapEntry)
    // MapEntry: field 1 = key (string), field 2 = value (Value)
    const structBytes: Uint8Array[] = [];
    for (const [key, val] of Object.entries(value)) {
      const keyBytes = encodeStringField(1, key);
      const valBytes = encodeMessageField(2, encodeProtobufValue(val));
      const mapEntry = concatBytes(keyBytes, valBytes);
      structBytes.push(encodeMessageField(1, mapEntry));
    }
    const structValue = concatBytes(...structBytes);
    return encodeMessageField(5, structValue);
  }

  // Fallback: encode as string
  return encodeStringField(3, String(value));
}

/**
 * Debug helper: dump protobuf bytes as hex string
 */
export function hexDump(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}
