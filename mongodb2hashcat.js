/*
 * This software is Copyright (c) 2016 AverageSecurityGuy <stephen at averagesecurityguy.info>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * https://averagesecurityguy.github.io/2016/04/29/finding-and-exploiting-mongodb/
 */

/*
 * date: October 2020
 * license: public domain, see license terms above
 * changes to support the SCRAM-SHA-256 variant by philsmd
 */

// Usage: mongo admin mongodb2john.js
//        mongo [hostname]:[port]/[database_name] mongodb2john.js

// how to create a test database and user:
// $ mongo
// use admin
// db.createUser ({user: "user", pwd: "hashcat", roles: ["readWrite","dbAdmin"]})

// extract the hash with this script like this:
// $ mongo admin mongodb2hashcat.js

// use this to disable SCRAM-SHA1 hash output:
// --eval 'var scramSHA1 = 0'

// use this to disable SCRAM-SHA256 hash output:
// --eval 'var scramSHA256 = 0'

// e.g. mongo admin --eval 'var scramSHA256 = 0' mongodb2hashcat.js

var outputSHA1hashes   = 1;
var outputSHA256hashes = 1;

if (typeof scramSHA1 != "undefined")
{
  if (scramSHA1 == 0)
  {
    outputSHA1hashes = 0;
  }
}

if (typeof scramSHA256 != "undefined")
{
  if (scramSHA256 == 0)
  {
    outputSHA256hashes = 0;
  }
}

try
{

  if (outputSHA1hashes == 1)
  {
    cursor = db.system.users.find ();

    while (cursor.hasNext ())
    {
      c = cursor.next ();

      s = c['credentials']['SCRAM-SHA-1'];

      if (!s) continue;

      h = '$mongodb-scram$*0*' + c['user'] + '*' + s['iterationCount'] + '*' + s['salt'] + '*' + s['serverKey'];

      print (h);
    }

    cursor.close ();
  }

  if (outputSHA256hashes == 1)
  {
    cursor = db.system.users.find ();

    while (cursor.hasNext ())
    {
      c = cursor.next ();

      s = c['credentials']['SCRAM-SHA-256'];

      if (!s) continue;

      h = '$mongodb-scram$*1*' + c['user'] + '*' + s['iterationCount'] + '*' + s['salt'] + '*' + s['serverKey'];

      print (h);
    }

    cursor.close ();
  }
}
catch (err) {}
