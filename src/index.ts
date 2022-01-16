import {Client, createClient} from 'ldapjs';

export interface StringMap {
  [key: string]: string;
}
export interface ClientOptions {
  url: string | string[];
  // tslint:disable-next-line:ban-types
  tlsOptions?: Object | undefined;
  socketPath?: string | undefined;
  log?: any;
  timeout?: number | undefined;
  connectTimeout?: number | undefined;
  idleTimeout?: number | undefined;
  reconnect?: boolean | {
      initialDelay?: number | undefined,
      maxDelay?: number | undefined,
      failAfter?: number | undefined
  } | undefined;
  strictDN?: boolean | undefined;
  queueSize?: number | undefined;
  queueTimeout?: number | undefined;
  queueDisable?: boolean | undefined;
  bindDN?: string | undefined;
  bindCredentials?: string | undefined;
}
export interface Config {
  options: ClientOptions;
  dn: string;
}
export interface Conf extends Config {
  users?: string;
  attributes?: string[];
  map?: StringMap;
}
export type LDAPConfig = Config;
export type LDAPConf = Config;
export interface User {
  username: string;
  password: string;
}
export interface Result {
  status: number | string;
  user?: Account;
  message?: string;
}
export interface Account {
  id?: string;
  username?: string;
  contact?: string;
  email?: string;
  phone?: string;
  displayName?: string;
  passwordExpiredTime?: Date;
  token?: string;
  tokenExpiredTime?: Date;
  newUser?: boolean;
  userType?: string;
  roles?: string[];
  privileges?: Privilege[];
  language?: string;
  dateFormat?: string;
  timeFormat?: string;
  gender?: string;
  imageURL?: string;
}
export interface Privilege {
  id?: string;
  name: string;
  resource?: string;
  path?: string;
  icon?: string;
  sequence?: number;
  children?: Privilege[];
  permissions?: number;
}
export interface Status {
  fail: number | string;
  success: number | string;
}
export function useLDAP<T extends User>(c: Conf, status: Status): (user: T) => Promise<Result> {
  if (c.users && c.users.length > 0) {
    const a = new MockAuthenticator<T>(c, status);
    return a.authenticate;
  } else {
    const client = createClient(c.options);
    const a = new Authenticator<T>(client, status, c.dn, c.attributes, c.map);
    return a.authenticate;
  }
}
export class Authenticator<T extends User> {
  map?: StringMap;
  constructor(public client: Client, public status: Status, public dn: string, public attributes?: string[], m?: StringMap) {
    this.map = m;
    this.authenticate = this.authenticate.bind(this);
  }
  authenticate(user: T): Promise<Result> {
    const dn = this.dn.replace('%s', user.username);
    return bind(this.client, dn, user.password, this.attributes, this.map).then(acc => {
      const keys = Object.keys(acc);
      if (keys.length > 0) {
        return {status : this.status.success, user: acc};
      } else {
        return {status : this.status.success};
      }
    }).catch(err => {
      return {status: this.status.fail, message: err.lde_message};
    });
  }
}
export const LDAPAuthenticator = Authenticator;
export function bind(client: Client, dn: string, password: string, attributes?: string[], m?: StringMap): Promise<Account> {
  return new Promise<Account>((resolve, reject) => {
    client.bind(dn, password, (er0: any) => {
      if (er0) {
        return reject(er0);
      } else {
        if (!attributes) {
          return resolve({} as Account);
        } else {
          const opts = {
            derefAliases: 0,
            filter: '(&(objectClass=*))',
            attributes,
            sizeLimit: 1,
            timeLimit: 0
          };
          client.search(dn, opts, (er1: any, res: { on: (arg0: string, arg1: (entry: { object: any; }) => void) => void; }) => {
            if (er1) {
              reject(er1);
            } else {
              res.on('searchEntry', (entry: { object: any; }) => {
                if (!m) {
                  return resolve(entry.object as Account);
                } else {
                  return resolve(map(entry.object, m) as Account);
                }
              });
            }
          });
        }
      }
    });
  });
}
export function map<T, R>(obj: T, m: StringMap): R {
  if (!m) {
    return obj as any;
  }
  const mkeys = Object.keys(m);
  const obj2: any = {};
  for (const key of mkeys) {
    let k0 = m[key];
    const v = (obj as any)[k0];
    if (v !== undefined) {
      k0 = key;
      obj2[key] = v;
    }
  }
  return obj2;
}
// tslint:disable-next-line:max-classes-per-file
export class MockAuthenticator<T extends User> {
  authenticator: Authenticator<T>;
  users?: string[];
  constructor(conf: Conf, public status: Status) {
    const client = createClient(conf.options);
    this.authenticator = new Authenticator<T>(client, status, conf.dn, conf.attributes, conf.map);
    if (conf.users && conf.users.length > 0) {
      this.users = conf.users.split(',');
    }
    this.authenticate = this.authenticate.bind(this);
  }
  authenticate(user: T): Promise<Result> {
    if (this.users) {
      for (const u of this.users) {
        if (user.username === u) {
          return Promise.resolve({status: this.status.success});
        }
      }
    }
    return this.authenticator.authenticate(user);
  }
}
