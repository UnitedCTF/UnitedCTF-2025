const Fastify = require('fastify');
const fastifyStatic = require('@fastify/static');
const fastifyMiddie = require('@fastify/middie');
const child_process = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const tmp = require('tmp');
const { EntropyPool } = require('./random');

const CHAR_BLACKLIST = /[^\d]/g;
const ENTROPY_POOL = new EntropyPool(256);
const ROOM_KEYS = new Map();

/* seed data */
ROOM_KEYS.set('CBG:13' , '393391c8ed6194e1');
ROOM_KEYS.set('CBG:200', 'cbe32befb6599df6');
ROOM_KEYS.set('CBG:582', '209fbe997f83affc');

/* utils */
// https://stackoverflow.com/questions/34309988/byte-array-to-hex-string-conversion-in-javascript
function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function validateRoomCode(roomCode) {
    if(!roomCode.startsWith('CBG:')) return false;
    if(CHAR_BLACKLIST.test(roomCode.substring(4))) return false;
    return true;
}

function validateRoomKey(roomCode, roomKey) {
    if(!ROOM_KEYS.has(roomCode)) return false;
    if(ROOM_KEYS.get(roomCode) != roomKey) return false;
    return true;
}

async function checkBreached(roomCode) {
    const configTemplate = fs.readFileSync('template.cfg').toString();
    const config = Buffer.from(configTemplate.replace('%s', roomCode));

    const configFile = tmp.fileSync();
    fs.writeSync(configFile.fd, config);

    const searchProc = child_process.spawn('/usr/bin/rg', ['breached-rooms.lst.gz'], {
        env: { 'RIPGREP_CONFIG_PATH': configFile.name }
    });

    const exitCode = await new Promise((resolve, _) => searchProc.on('close', resolve));

    configFile.removeCallback();

    switch(exitCode) {
        case 0:
            return true;
        case 1:
            return false;
        default:
            throw new Error();
    }
}

async function getBreachedCount() {
    const countProc = child_process.spawn('/bin/sh', ['-c', '/bin/gzip -cd breached-rooms.lst.gz | /usr/bin/wc -l']);
    const stdoutRes = await new Promise((resolve, _) => countProc.stdout.on('data', resolve));

    return parseInt(stdoutRes.toString());
}

function resetRoomKey(roomCode) {
    const newRoomKey = toHexString(ENTROPY_POOL.getRandomBytes(8));
    ENTROPY_POOL.reseed();

    ROOM_KEYS.set(roomCode, newRoomKey);
}

/* web server */
const fastify = Fastify({
    logger: true
});

fastify.register(fastifyStatic, {
    root: path.join(__dirname, 'public')
});

fastify.register(fastifyMiddie);

fastify.addHook('onRequest', async (req, _) => {
    const userAgent = req.headers['user-agent'] || '';
    const url = req.url || '';
    const body = req.body || '';

    const entropy = Buffer.from(`${Date.now()}${userAgent}${url}${body}`);
    ENTROPY_POOL.addEntropy(entropy);
});

fastify.get('/api/info', async (_, reply) => {
    const breachedCount = await getBreachedCount();

    reply.status(200).send({
        version: '1.0.0',
        breachedCount
    });
});

fastify.post('/api/check', {
    handler: async (req, reply) => {
        const { roomCode, roomKey } = req.body;

        if(!validateRoomCode(roomCode)) {
            reply.status(400).send({ error: 'invalid room code, must follow format CBG:<room_number>' });
            return;
        }

        if(!validateRoomKey(roomCode, roomKey)) {
            reply.status(401).send({ error: 'incorrect room key' });
            return;
        }

        try {
            const isBreached = await checkBreached(roomCode);
            reply.status(200).send({ breached: isBreached });
        } catch {
            reply.status(500).send({ error: 'an internal error has occurred' })
        }
    },
    schema: {
        body: {
            type: 'object',
            required: ['roomCode', 'roomKey'],
            properties: {
                roomCode: {
                    type: 'string',
                    minLength: 4,
                    maxLength: 24
                },
                roomKey: {
                    type: 'string',
                    minLength: 16,
                    maxLength: 16
                }
            }
        }
    }
});

fastify.post('/api/reset', {
    handler: async (req, reply) => {
        const { roomCode } = req.body;
        resetRoomKey(roomCode);

        reply.status(200).send({});
    },
    schema: {
        body: {
            type: 'object',
            required: ['roomCode'],
            properties: {
                'roomCode': {
                    type: 'string',
                    minLength: 4,
                    maxLength: 24
                }
            }
        }
    }
})

const start = async () => {
    try {
        await fastify.listen({
            host: '0.0.0.0',
            port: 3000
        });
    } catch(err) {
        fastify.log.error(err);
        process.exit(1);
    }
};
start();