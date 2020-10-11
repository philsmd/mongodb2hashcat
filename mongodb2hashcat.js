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

// Usage: mongo admin mongodb2hashcat.js
//        mongo [hostname]:[port]/[database_name] mongodb2hashcat.js

// how to create a test database and user:
// $ mongo
// use admin
// db.createUser ({user: "user", pwd: "hashcat", roles: ["readWrite","dbAdmin"]})

// extract the hash with this script like this:
// $ mongo --quiet admin mongodb2hashcat.js

// use this to disable SCRAM-SHA1 hash output:
// --eval 'var scramSHA1 = 0'

// use this to disable SCRAM-SHA256 hash output:
// --eval 'var scramSHA256 = 0'

// use this to load the data from a JSON dump file:
// --eval 'var dumpFile = "users.json"'

// use this to prepend the user id record to each hash:
// --eval 'var withID = 1'

// e.g. something like this:
// $ mongo --quiet --eval 'var scramSHA256 = 0' admin mongodb2hashcat.js

// to combine multiple parameters use a semicolon:
// $ mongo --quiet --eval 'var scramSHA1 = 0; var dumpFile = "a.json"' admin mongodb2hashcat.js

/*
 * Helper functions:
 */

function base64Encode (input)
{
  var BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

  var output = '';

  for (var i = 0; i < input.length; i += 3)
  {
    var c0 = input.charCodeAt (i + 0);
    var c1 = input.charCodeAt (i + 1);
    var c2 = input.charCodeAt (i + 2);

    var a =                  c0 >> 2;
    var b = (c0 &  3) << 4 | c1 >> 4;
    var c = (c1 & 15) << 2 | c2 >> 6;
    var d = (c2 & 63);

    if (! c1) // or isNaN ()
    {
      c = 64; // =
      d = 64; // =
    }
    else if (! c2) // or isNaN ()
    {
      d = 64; // =
    }

    output += BASE64_TABLE.charAt (a)
           +  BASE64_TABLE.charAt (b)
           +  BASE64_TABLE.charAt (c)
           +  BASE64_TABLE.charAt (d);
  }

  return output;
}

class Cursor
{
  constructor (str)
  {
    this.items = JSON.parse (str);
    this.size  = this.items.length;
    this.index = 0;
  }

  hasNext ()
  {
    return this.size > this.index;
  }

  isExhausted ()
  {
    return false; // never the case
  }

  next ()
  {
    return this.items[this.index++];
  }

  close ()
  {
    this.index = 0; // reset
  }
}

/*
 * Start
 */

var outputID           = false;
var outputSHA1hashes   = true;
var outputSHA256hashes = true;

if (typeof withID != 'undefined')
{
  if (withID) outputID = true;
}

if (typeof scramSHA1 != 'undefined')
{
  if (! scramSHA1) outputSHA1hashes = false;
}

if (typeof scramSHA256 != 'undefined')
{
  if (! scramSHA256) outputSHA256hashes = false;
}

var hashTypes = [
  {
    name:    'SCRAM-SHA-1',
    enabled: outputSHA1hashes
  },
  {
    name:    'SCRAM-SHA-256',
    enabled: outputSHA256hashes
  }
]

var cursor = undefined;

if (typeof dumpFile != 'undefined')
{
  try
  {
    var fileContent = cat (dumpFile);

    // work around a JSON.parse () error with 'UUID ("id")':

    fileContent = fileContent.replace (new RegExp ('UUID\\(', 'g'), '');
    fileContent = fileContent.replace (new RegExp ('\\),',    'g'), ',');

    // we need to create a fake array (multiple {} objects separated by ",")
    // if we have more than one (1) single user:

    fileContent = '[' + fileContent + ']';

    fileContent = fileContent.replace (new RegExp ('}[\r\n]\+{', 'g'), '},\n{');

    cursor = new Cursor (fileContent);
  }
  catch (err)
  {
    print (err);

    quit ();
  }
}

try
{
  // print the user hashes in order:
  // - first SHA1-based hashes,
  // - then SHA256-based hashes

  if (! cursor) cursor = db.system.users.find (); // query the database

  for (var i = 0; i < hashTypes.length; i++)
  {
    var hashTypeAlgoName = hashTypes[i].name;
    var hashTypeEnabled  = hashTypes[i].enabled;

    if (! hashTypeEnabled) continue;

    if (cursor.isExhausted ()) cursor = db.system.users.find ();

    while (cursor.hasNext ())
    {
      var c = cursor.next ();

      if (! c) break;

      var t = c['credentials'];

      if (! t) continue;

      var s = t[hashTypeAlgoName];

      if (! s) continue;

      var user = c['user'];
      var iter = s['iterationCount'];
      var salt = s['salt'];
      var sKey = s['serverKey'];

      if (! user) continue;

      user = base64Encode (user);

      if (! iter) continue;
      if (! salt) continue;
      if (! sKey) continue;

      var idField = '';

      if (outputID)
      {
        var userID = c['_id'];

        if (userID) idField = userID;

        idField += ':';
      }

      var hash = '$mongodb-scram$' + '*' +
                                 i + '*' +
                              user + '*' +
                              iter + '*' +
                              salt + '*' +
                              sKey;

      print (idField + hash);
    }

    cursor.close ();
  }
}
catch (err) {}
