# About

The goal of this project is to make it very easy to extract hashes from the MongoDB database server to a hash format that `hashcat` accepts: -m 24100 or -m 24200

# Requirements

Software:
- MongoDB server and client must be installed (should work on any supported operating system)

# Installation and first steps

* Clone this repository:
    git clone https://github.com/philsmd/mongodb2hashcat.git
* Enter the repository root folder:
    cd mongodb2hashcat
* Run it:
    mongo admin mongodb2hashcat.js
* Copy output to a file (or redirect output to a file (>) directly) and run it with `hashcat` using mode -m 24100 = `MongoDB ServerKey SCRAM-SHA-1` or -m 24200 = `MongoDB ServerKey SCRAM-SHA-256`

If the output of `mongodb2hashcat` starts with `$mongodb-scram$*0` then you need to use hash mode -m 24100, for `$mongodb-scram$*1` use -m 24200 instead.

# Usage and parameters

The usage is very simple:
  mongo admin mongodb2hashcat.js

You can also instruct the script to only export a certain type of hash:
   mongo admin --eval 'var scramSHA256 = 0' mongodb2hashcat.js
   mongo admin --eval 'var scramSHA1   = 0' mongodb2hashcat.js

You can redirect the output like this:
   mongo admin --eval 'var scramSHA256 = 0' mongodb2hashcat.js > m24100\_hashes.txt
   mongo admin --eval 'var scramSHA1   = 0' mongodb2hashcat.js > m24200\_hashes.txt

# Explanation of the hash format

if the backup was generated with SCRAM-SHA-1:
 $mongodb-scram$\*0\*user\_name\*iter\*base64\_salt\*base64\_digest

SCRAM-SHA-256 hashes:
 $mongodb-scram$\*1\*user\_name\*iter\*base64\_salt\*base64\_digest

# Hacking / Missing features

* more features
* improvements and all bug fixes are very welcome

# Credits and Contributors

Credits go to:

* AverageSecurityGuy, philsmd, hashcat project

# License/Disclaimer

License: This software is Copyright (c) 2016 AverageSecurityGuy and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.

https://averagesecurityguy.github.io/2016/04/29/finding-and-exploiting-mongodb/

adapted and updated by philsmd for the SCRAM-SHA-256 variant of the hashes.

Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE