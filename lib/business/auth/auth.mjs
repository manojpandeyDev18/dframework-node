import crypto from 'crypto';
import BusinessBase from '../business-base.mjs';

const CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/

const USER_PASS_REGEXP = /^([^:]*):(.*)$/

class Auth {
    async getUserFromDatabase(username) {
        const sql = BusinessBase.businessObject.sql;
        const request = new BusinessBase().createRequest();
        let query = `SELECT su.Username, su.EmailAddress, su.RoleId, su.UserId, su.PasswordHash, su.DashboardPreference, ru.Name AS RoleName FROM Security_User su JOIN Security_Role ru ON su.RoleId = ru.RoleId WHERE su.EmailAddress=@_username AND su.IsActive=1;`;
        query = sql.addParameters({ query: query, request, parameters: { _username: username }, forWhere: false });
        const user = await sql.runQuery({ request, type: 'query', query });
        if (!user.data.length) {
            throw new Error(`User not found: ${username}`);
        }
        return user.data[0];
    }
    async getMenuData(roleId) {
        const sql = BusinessBase.businessObject.sql;
        const menuData = await sql.query(`SELECT * FROM vwRoleMenuList WHERE RoleId = ${roleId} AND IsActive = 1;`);
        return menuData.filter(item => item.Permission1 !== 0);
    }
    hashPassword(pwd) {
        const hash = crypto.createHash('sha256');
        hash.update(pwd);
        return hash.digest('hex');
    }
    getAuthorizationHeader (req) {
        if (!req) {
            throw new TypeError('argument req is required');
        }

        if (typeof req !== 'object') {
            throw new TypeError('argument req is required to be an object');
        }

        if (!req.headers || typeof req.headers !== 'object') {
            throw new TypeError('argument req is required to have headers property');
        }

        // get header
        const header = req.headers.authorization;

        // parse header
        return this.parse(header);
    }
    parse(header) {
        if (typeof header !== 'string') {
            return undefined
        }

        // parse header
        const match = CREDENTIALS_REGEXP.exec(header)

        if (!match) {
            return undefined
        }

        // decode user pass
        const decoded = Buffer.from(match[1], 'base64').toString();
        const userPass = USER_PASS_REGEXP.exec(decoded)

        if (!userPass) {
            return undefined
        }

        // return credentials object
        return {
            user: userPass[1],
            password: userPass[2]
        };
    }

};

export default Auth;