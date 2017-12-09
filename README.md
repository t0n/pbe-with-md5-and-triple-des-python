# "PBE With MD5 And Triple DES" implementation for Python 3

Python implementation of PBEWithMD5AndTripleDES algorithm, like the one used in Jasypt (Java lib).

While plain DES version (also included) uses simple iterative MD5 hashing of salt + password to generate derived key
and initialization vector, DES3 version needs bigger key so the logic is different (halves of salt are hashed
with password separately, then 2 16-byte MD5 hashes are joined together to provide 24-byte DK and 8-byte IV).

All MD5 hashing loops use 1000 cycles count.