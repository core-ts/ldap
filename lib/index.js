"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ldapjs_1 = require("ldapjs");
function useLDAP(c, status) {
  if (c.users && c.users.length > 0) {
    var a = new MockAuthenticator(c, status);
    return a.authenticate;
  }
  else {
    var client = ldapjs_1.createClient(c.options);
    var a = new Authenticator(client, status, c.dn, c.attributes, c.map);
    return a.authenticate;
  }
}
exports.useLDAP = useLDAP;
var Authenticator = (function () {
  function Authenticator(client, status, dn, attributes, m) {
    this.client = client;
    this.status = status;
    this.dn = dn;
    this.attributes = attributes;
    this.map = m;
    this.authenticate = this.authenticate.bind(this);
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
var MockAuthenticator = (function () {
  function MockAuthenticator(conf, status) {
    this.status = status;
    var client = ldapjs_1.createClient(conf.options);
    this.authenticator = new Authenticator(client, status, conf.dn, conf.attributes, conf.map);
    if (conf.users && conf.users.length > 0) {
      this.users = conf.users.split(',');
    }
    this.authenticate = this.authenticate.bind(this);
  }
  MockAuthenticator.prototype.authenticate = function (user) {
    if (this.users) {
      for (var _i = 0, _a = this.users; _i < _a.length; _i++) {
        var u = _a[_i];
        if (user.username === u) {
          return Promise.resolve({ status: this.status.success });
        }
      }
    }
    return this.authenticator.authenticate(user);
  };
  return MockAuthenticator;
}());
exports.MockAuthenticator = MockAuthenticator;
