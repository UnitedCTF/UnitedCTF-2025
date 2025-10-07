from z3 import * 

def is_prime(n):
  precalculated_primes = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 
    211, 223, 227, 229, 233, 239, 241, 251
  }
  return n in precalculated_primes


s = Solver()
min_length = 12
max_length = 30
alphabet = range(35, 122)
consonants = [ord(c) for c in 'bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ']
vowels = [ord(c) for c in 'aeioyu']
prime_codes = [p for p in range(35, 122) if is_prime(p)]

chars = [Int(f"c{i}") for i in range(max_length)]
bchars = [BitVec(f"bc{i}", 8) for i in range(max_length)]
length = Int("length")


# Password length must be between 12 and 30 character
s.add(And(length >= min_length, length <= max_length))


# All characters must have ASCII codes between 35 and 122
for i in range(max_length):
  s.add(Implies(i < length, And(chars[i] >= 35, chars[i] <= 122)))


# The sum of character ASCII codes times its position + 1 must equal 
# 18943
s.add(Sum([chars[i] * (i+1) for i in range(max_length)]) == 18943)


# Password must start with "flag-
for i, c in enumerate("flag-"):
  s.add(chars[i] == ord(c))


# Exactly six characters must have prime ASCII codes
s.add(Sum([
  If(And(i < length, Or([chars[i] == p for p in prime_codes])), 1, 0)
  for i in range(max_length)]) == 6)


# Must use exactly 17 unique characters
appear = [Bool(f"use_{c}") for c in alphabet]
for idx, c in enumerate(alphabet):
  s.add(appear[idx] == Or([
    And(i < length, chars[i] == c) 
    for i in range(max_length)
  ]))
s.add(Sum([If(a, 1, 0) for a in appear]) == 17)


# Exactly 14 lowercase letters
s.add(Sum([
  If(And(lettre >= 97, lettre <= 122), 1, 0) 
  for lettre in chars
]) == 14)


# An '@' character must be present and come before any digit
for i in range(max_length):
  s.add(Implies(
    And(chars[i] >= ord('0'), chars[i] <= ord('9')), 
     Or([chars[j] == ord('@') for j in range(i)])))


# Exactly one '-' character
s.add(Sum([
  If(And(i < length, chars[i] == ord('-')), 1, 0)
  for i in range(max_length)
]) == 1)


# At least two digits are required
s.add(Sum([
  If(And(i < length, chars[i] >= ord('0'), chars[i] <= ord('9')), 1, 0)
  for i in range(max_length)
]) >= 2)


# The sum of character ASCII codes modulo 287 must be 118
s.add(Sum([
  If(i < length, chars[i], 0) 
  for i in range(max_length)
]) % 287 == 118)


# The sum of character ASCII codes at even indices must be 875
s.add(Sum([
  If(And(i < length, i % 2 == 0), chars[i], 0) 
  for i in range(max_length)
]) == 875)


# The alternating sum of character ASCII codes must be -90
s.add(Sum([
  If(i < length, (-1)**i * chars[i], 0) 
  for i in range(max_length)
]) == -90)


# The XOR of characters at positions 13 and 19 must differ from the 
# XOR of characters at positions 14 and 18
for i in range(max_length):
  s.add(bchars[i] == Int2BV(chars[i], 8))

# Exactly 4 vowels (a or A)
s.add(Sum([
  If(And(i < length, Or([
    chars[i] == v 
    for v in [ord(c) for c in 'aA']
  ])), 1, 0)
  for i in range(max_length)
]) == 4)


# (char[11]^3) % 256 > (char[12] - 57)
s.add((bchars[11] * bchars[11] * bchars[11]) % 256 > (bchars[12] - 57))

# Character at position 18 must be 'Z'
s.add(chars[18] == ord('Z'))


# Character at position 19 must be '3'
s.add(chars[19] == ord('3'))


# Must contain the substring "vec"
s.add(Or([
  And(i + 3 <= length,
    chars[i] == ord('v'),
    chars[i+1] == ord('e'), 
    chars[i+2] == ord('c'))
  for i in range(max_length - 2)
]))


# No two consecutive lowercase vowels
for i in range(max_length - 1):
  s.add(Implies(And(i + 1 < length, Or([chars[i] == v for v in vowels])), 
                Not(Or([chars[i+1] == v for v in vowels]))))


# No uppercase letters before position 12
for i in range(12):
  s.add(Implies(i < length, 
                Not(And(chars[i] >= ord('A'), chars[i] <= ord('Z')))))


# # Exactly 2 non-alphanumeric characters
s.add(Sum([
  If(And(i < length, Not(Or(
    And(chars[i] >= ord('a'), chars[i] <= ord('z')),
    And(chars[i] >= ord('A'), chars[i] <= ord('Z')),
    And(chars[i] >= ord('0'), chars[i] <= ord('9'))
  ))), 1, 0)
  for i in range(max_length)
]) == 2)


# char[8] - char[6] == char[10] - char[8]
s.add(chars[8] - chars[6] == chars[10] - chars[8])


# Character at position 12 must be '0'
s.add(chars[12] == ord('0'))


# Must contain the substring "l@"
s.add(Or([
  And(i + 2 <= length,
    chars[i] == ord('l'),
    chars[i+1] == ord('@'))
  for i in range(max_length - 1)
]))


# At most two occurrence of two consecutive consonants
double_consonant_positions = [
  And(i + 2 <= length,
    Or([chars[i] == c for c in consonants]),
    Or([chars[i+1] == c for c in consonants]))
  for i in range(max_length - 1)
]
s.add(Sum([If(cond, 1, 0) for cond in double_consonant_positions]) <= 2)


# Must contain a pattern like "ala" with variants (a => aA@, l => lL1!)
a_variants = [ord(c) for c in 'aA@']
l_variants = [ord(c) for c in 'lL1!']
s.add(Or([
  And(i + 2 < length,
    Or([chars[i] == v for v in a_variants]),
    Or([chars[i+1] == v for v in l_variants]),
    Or([chars[i+2] == v for v in a_variants]))
  for i in range(max_length - 2)
]))


# # Must not contain the substring "mo"
s.add(Not(Or([
  And(i + 2 <= length,
    chars[i] == ord('m'),
    chars[i+1] == ord('o'))
  for i in range(max_length - 1)
])))


# The character \'A\' cannot be followed by 'o', 'u', or 'a' anywhere 
# in the string
for i in range(max_length):
  for j in range(i + 1, max_length):
    s.add(Implies(
      And(i < length, j < length, chars[i] == ord('A')), 
      chars[j] != ord('o')))
    s.add(Implies(
      And(i < length, j < length, chars[i] == ord('A')),
      chars[j] != ord('u')))
    s.add(Implies(
      And(i < length, j < length, chars[i] == ord('A')),
      chars[j] != ord('a')))
              

# The character 'u' cannot be followed by 'a' or 'o' anywhere in the 
# string
for i in range(max_length):
  for j in range(i + 1, max_length):
    s.add(Implies(
      And(i < length, j < length, chars[i] == ord('u')),
      chars[j] != ord('a')))
    s.add(Implies(
      And(i < length, j < length, chars[i] == ord('u')),
      chars[j] != ord('o')))
              

# Must contain the substring "-al"
s.add(Or([
  And(i + 2 < length,
    chars[i] == ord('-'),
    chars[i+1] == ord('a'),
    chars[i+2] == ord('l'))
  for i in range(max_length - 2)
]))


if s.check() == sat:
  m = s.model()
  n = m[length].as_long()
  result = ''.join([chr(m[chars[i]].as_long()) for i in range(n)])
  print(result)