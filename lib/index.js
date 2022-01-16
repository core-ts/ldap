"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Authenticator = (function () {
  function Authenticator(client, status, dn, options, attributes, m) {
    this.client = client;
    this.status = status;
    this.dn = dn;
    this.options = options;
    this.attributes = attributes;
    this.map = m;
  }
  Authenticator.prototype.authenticate = function (user) {
    var _this = this;
    var dn = this.dn.replace('%s', user.username);
    return bind(this.client, dn, user.password, this.attributes, this.map).then(function (acc) {
      var keys = Object.keys(acc);
      if (keys.length > 0) {
        return { status: _this.status.success, user: acc };
      }
      else {
        return { status: _this.status.success };
      }
    }).catch(function (err) {
      return { status: _this.status.fail, message: err.lde_message };
    });
  };
  return Authenticator;
}());
exports.Authenticator = Authenticator;
exports.LDAPAuthenticator = Authenticator;
function bind(client, dn, password, attributes, m) {
  return new Promise(function (resolve, reject) {
    client.bind(dn, password, function (er0) {
      if (er0) {
        return reject(er0);
      }
      else {
        if (!attributes) {
          return resolve({});
        }
        else {
          var opts = {
            derefAliases: 0,
            filter: '(&(objectClass=*))',
            attributes: attributes,
            sizeLimit: 1,
            timeLimit: 0
          };
          client.search(dn, opts, function (er1, res) {
            if (er1) {
              reject(er1);
            }
            else {
              res.on('searchEntry', function (entry) {
                if (!m) {
                  return resolve(entry.object);
                }
                else {
                  return resolve(map(entry.object, m));
                }
              });
            }
          });
        }
      }
    });
  });
}
exports.bind = bind;
function map(obj, m) {
  if (!m) {
    return obj;
  }
  var mkeys = Object.keys(m);
  var obj2 = {};
  for (var _i = 0, mkeys_1 = mkeys; _i < mkeys_1.length; _i++) {
    var key = mkeys_1[_i];
    var k0 = m[key];
    var v = obj[k0];
    if (v !== undefined) {
      k0 = key;
      obj2[key] = v;
    }
  }
  return obj2;
}
exports.map = map;
