/**
 * Takes two given `ArrayBuffer` of identical lengths and performs an XOR operation between each element
 * @param leftBuffer
 * @param rightBuffer
 * @returns The results of the XOR between two `ArrayBuffer`s
 */
export function xorArrayBuffer(leftBuffer: ArrayBuffer, rightBuffer: ArrayBuffer) {
    const resultBuffer = new ArrayBuffer(leftBuffer.byteLength);
    const result = new Uint8Array(resultBuffer);
    const left = new Uint8Array(leftBuffer);
    const right = new Uint8Array(rightBuffer);
    for (let i = 0; i < left.length; i++) {
        result[i] = left[i] ^ right[i];
    }
    return result;
}
