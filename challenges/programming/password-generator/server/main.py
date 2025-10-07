from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

def is_prime(n):
  precalculated_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251}
  return n in precalculated_primes

def is_consonant(c):
  consonants = 'bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ'
  return c in consonants
  
  
def has_ala_pattern(x):
  a_variants = 'aA@'
  l_variants = 'lL1!'
    
  for i in range(len(x) - 2):
    if (x[i] in a_variants and 
      x[i+1] in l_variants and 
      x[i+2] in a_variants):
      return True
  return False


steps = [
  ('Password length must be between 12 and 30 characters', lambda x: 12 <= len(x) <= 30),
  ('All characters must have ASCII codes between 35 and 122', lambda x: all(35 <= ord(c) <= 122 for c in x)),
  ('The sum of character ASCII codes times its position + 1 must equal 18943', lambda x: sum((i+1) * ord(c) for i, c in enumerate(x)) == 18943),
  ('Password must start with "flag-"', lambda x: x.startswith("flag-")),
  ('Exactly six characters must have prime ASCII codes', lambda x: sum(1 for c in x if is_prime(ord(c))) == 6),
  ('Must use exactly 17 unique characters', lambda x: len(set(x)) == 17),
  ('Exactly 14 lowercase letters', lambda x: sum(1 for c in x if 'a' <= c <= 'z') == 14),
  ('An \'@\' character must be present and come before any digit', lambda x: '@' in x and all(x.index('@') < i for i, c in enumerate(x) if '0' <= c <= '9')),
  ('Exactly one \'-\' character', lambda x: x.count('-') == 1),
  ('At least two digits are required', lambda x: sum(1 for c in x if '0' <= c <= '9') >= 2),
  ('The sum of character ASCII codes modulo 287 must be 118', lambda x: sum(ord(c) for c in x) % 287 == 118),
  ('The sum of character ASCII codes at even indices must be 875', lambda x: sum(ord(c) for i, c in enumerate(x) if i % 2 == 0) == 875),
  ('The alternating sum of character ASCII codes must be -90', lambda x: sum((-1)**i * ord(c) for i, c in enumerate(x)) == -90),
  ('The XOR of characters at positions 13 and 19 must differ from the XOR of characters at positions 14 and 18', lambda x: len(x) >= 20 and ord(x[13]) ^ ord(x[19]) != ord(x[14]) ^ ord(x[18])),
  ('Exactly 4 characters in "aA"', lambda x: sum(1 for c in x if c in 'aA') == 4),
  ('(char[11]³) % 256 > (char[12] - 57)', lambda x: len(x) >= 13 and (ord(x[11])**3) % 256 > (ord(x[12]) - 57)),
  ('Character at position 18 must be \'Z\'', lambda x: len(x) >= 19 and x[18] == 'Z'),
  ('Character at position 19 must be \'3\'', lambda x: len(x) >= 20 and x[19] == '3'),
  ('Must contain the substring "vec"', lambda x: "vec" in x),
  ('No two consecutive lowercase vowels', lambda x: not any(x[i] in 'aeioyu' and x[i+1] in 'aeioyu' for i in range(len(x)-1))),
  ('No uppercase letters before position 12', lambda x: all(not ('A' <= c <= 'Z') for c in x[:min(12, len(x))])),
  ('Exactly 2 non-alphanumeric characters', lambda x: sum(1 for c in x if not (c.isalnum())) == 2),
  ('char[8] - char[6] == char[10] - char[8]', lambda x: len(x) >= 11 and ord(x[8]) - ord(x[6]) == ord(x[10]) - ord(x[8])),
  ('Character at position 12 must be \'0\'', lambda x: len(x) >= 13 and x[12] == '0'),
  ('Character at position 5 must be \'a\'', lambda x: len(x) >= 6 and x[5] == 'a'),
  ('Must contain the substring "l@"', lambda x: "l@" in x),
  ('At most two occurrence of two consecutive consonants', lambda x: sum(1 for i in range(len(x)-1) if is_consonant(x[i]) and is_consonant(x[i+1])) <= 2),
  ('Must contain a pattern like "ala" with variants (a => aA@, l => lL1!)', lambda x: has_ala_pattern(x)),
  ('Must not contain the substring "mo"', lambda x: "mo" not in x),
  ('The character \'A\' cannot be followed by \'o\', \'u\', or \'a\' anywhere in the string', lambda x: all(not (x[i] == 'A' and i + 1 < len(x) and x[i + 1] in 'oua') for i in range(len(x)))),
  ('The character \'u\' cannot be followed by \'a\' or \'o\' anywhere in the string', lambda x: all(not (x[i] == 'u' and i + 1 < len(x) and x[i + 1] in 'ao') for i in range(len(x)))),
  ('Must contain the substring "-al"', lambda x: "-al" in x)
]


@app.route("/", methods=["GET"])
def home():
  return render_template("index.html")
  

@app.route("/password", methods=["POST"])
def password():
  data = request.get_json() or {}
  password = data.get("password", "")
  messages = []
  alert = []
  
  for i, (msg, check) in enumerate(steps):
    messages.append(msg)
    if not check(password):
      if i > 3:
        alert.append("flag-ssssssTr000NNNNNNGGG-pa$$word (1/2)")
      return jsonify({"messages": messages, "alert": alert})
  
  return jsonify({"messages": [msg for msg, _ in steps] + ["Congratulations! You've found the correct password."]})


if __name__ == "__main__":
    app.run(host='0.0.0.0')

