const crypto = require('node:crypto');

class EntropyPool {
    constructor(size) {
        this.size = size;
        this.cursor = 0;
        this.reseed();
    }

    reseed() {
        this.buffer = crypto.randomBytes(this.size);
    }

    addEntropy(data) {
        for(let i = 0; i < data.length; i++) {
            this.buffer[this.cursor++ % this.size] = data[i];
        }
    }

    getRandomBytes(length) {
        const data = new Uint8Array(length);
        for(let i = 0; i < data.length; i++) {
            const sampled = this.buffer[Math.floor(Math.random() * this.buffer.length)];
            data[i] = sampled;
        }
        return data;
    }
}

module.exports = { EntropyPool }