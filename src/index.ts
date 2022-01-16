import {Client} from 'ldapjs';

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
export class Authenticator<T extends User> {
  map?: StringMap;
  constructor(public client: Client, public status: Status, public dn: string, public options: ClientOptions, public attributes?: string[], m?: StringMap) {
    this.map = m;
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
