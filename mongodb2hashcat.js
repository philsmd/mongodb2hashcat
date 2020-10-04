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

/*
 * Helper functions:
 */

function base64Encode (input)
{
  var BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  var output = "";

  for (var i = 0; i < input.length; i += 3)
  {
    var c0 = input.charCodeAt (i + 0);
    var c1 = input.charCodeAt (i + 1);
    var c2 = input.charCodeAt (i + 2);

    var f = c0 >> 2;

    var a = (c0 &  3) << 4 | c1 >> 4;
    var b = (c1 & 15) << 2 | c2 >> 6;
    var c = (c2 & 63);

    if (isNaN (c1))
    {
      b = 64; // =
      c = 64; // =
    }
    else if (isNaN (c2))
    {
      c = 64; // =
    }

    output += BASE64_TABLE.charAt (f)
           +  BASE64_TABLE.charAt (a)
           +  BASE64_TABLE.charAt (b)
           +  BASE64_TABLE.charAt (c);
  }

  return output;
}

/*
 * Start
 */

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
    var cursor = db.system.users.find ();

    while (cursor.hasNext ())
    {
      var c = cursor.next ();

      var s = c['credentials']['SCRAM-SHA-1'];

      if (!s) continue;

      var u = base64Encode (c['user']);

      var h = '$mongodb-scram$*0*' + u + '*' + s['iterationCount'] + '*' + s['salt'] + '*' + s['serverKey'];

      print (h);
    }

    cursor.close ();
  }

  if (outputSHA256hashes == 1)
  {
    var cursor = db.system.users.find ();

    while (cursor.hasNext ())
    {
      var c = cursor.next ();

      var s = c['credentials']['SCRAM-SHA-256'];

      if (!s) continue;

      var u = base64Encode (c['user']);

      var h = '$mongodb-scram$*1*' + u + '*' + s['iterationCount'] + '*' + s['salt'] + '*' + s['serverKey'];

      print (h);
    }

    cursor.close ();
  }
}
catch (err) {}
