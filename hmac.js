const opad = 0x5c;
const ipad = 0x36;

/**
 * Returns a new buffer padded with the new length
 * @param {Buffer} buffer Buffer to pad
 * @returns {Buffer} padded buffer
 */
function padZero(buffer){
    let newBuf = Buffer.alloc(buffer.byteLength);
    buffer.copy(newBuf);
    return newBuf;
}
/**
 * Creates a buffer filled with value
 * @param {number} length The length of the new buffer
 * @param {number} value The value which the buffer will be filled
 * @returns {Buffer}
 */
function allocFill(length, value){
    return Buffer.alloc(length).fill(value);
}
/**
 * Creates a buffer with `Math.max(buf1.byteLength, buf2.byteLength)` length and does a xor operation with buf1 and buf2 contents
 * @param {Buffer} buf1 Buffer 1
 * @param {Buffer} buf2 Buffer 2
 * @returns {Buffer} New buffer with (buf1 ^ buf2)
 */
function bufferXor(buf1, buf2){
    const newBuf = Buffer.alloc(Math.max(buf1.byteLength, buf2.byteLength));
    for(let i=0;i<newBuf.byteLength;i++){
        newBuf[i] = buf1[i] ^ buf2[i];
    }
    return newBuf;
}






// Synchronous version
/**
 * Computes the blockSized (k') of the key (k)
 * @param {Buffer} key Key buffer
 * @param {(content: Buffer) => Buffer} hash Hash function (sync function)
 * @param {number} blockSize Blocksize of the hash function (e.g 64 bytes for SHA-1)
 * @returns {Buffer} Blocksized key
 */
function computeBlockSizedKey(key, hash, blockSize){
    if(key.length > blockSize){
        key = hash(key);
    }
    if(key.length < blockSize){
        return padZero(key, blockSize);
    }
    return key;
}
/**
 * Generates a HMAC digest with message and key (synchronous version)
 * @param {Buffer} message Message buffer
 * @param {Buffer} key Key buffer 
 * @param {(content: Buffer) => Buffer} hash Hash function (sync function)
 * @param {number} blockSize Blocksize of the hash function (e.g 64 bytes for SHA-1)
 * @returns {Buffer} The HMAC message
 */
function hmacSync(message, key, hash, blockSize){
    let blockSizedKey = computeBlockSizedKey(key, hash, blockSize);
    let o_key_pad = bufferXor(blockSizedKey, allocFill(blockSize, opad));
    let i_key_pad = bufferXor(blockSizedKey, allocFill(blockSize, ipad));

    return hash(Buffer.concat([o_key_pad, hash(Buffer.concat([i_key_pad, message]))]));
}




// Asynchronous version
/**
 * Computes the blockSized (k') of the key (k)
 * @param {Buffer} key Key buffer
 * @param {(content: Buffer) => Promise<Buffer>} hash Hash function (async function)
 * @param {number} blockSize Blocksize of the hash function (e.g 64 bytes for SHA-1)
 * @returns {Promise<Buffer>} Blocksized key
 */
async function computeBlockSizedKeyAsync(key, hash, blockSize){
    if(key.length > blockSize){
        key = await hash(key);
    }
    if(key.length < blockSize){
        return padZero(key, blockSize);
    }
    return key;
}
/**
 * Generates a HMAC digest with message and key (asynchronous/promise version)
 * @param {Buffer} message Message buffer
 * @param {Buffer} key Key buffer 
 * @param {(content: Buffer) => Promise<Buffer>} hash Hash function (async function)
 * @param {number} blockSize Blocksize of the hash function (e.g 64 bytes for SHA-1)
 * @returns {Promise<Buffer>} The HMAC message
 */
async function hmac(message, key, hash, blockSize){
    let blockSizedKey = await computeBlockSizedKeyAsync(key, hash, blockSize);
    let o_key_pad = bufferXor(blockSizedKey, allocFill(blockSize, opad));
    let i_key_pad = bufferXor(blockSizedKey, allocFill(blockSize, ipad));

    return await hash(Buffer.concat([o_key_pad, await hash(Buffer.concat([i_key_pad, message]))]));
}

module.exports = {
    hmac,
    hmacSync
};