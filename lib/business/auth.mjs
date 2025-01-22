import BasicAuth from './auth/basicAuth.mjs';
import EntraIdAuth from './auth/entraAuth.mjs';
import LdapAuth from './auth/ldapAuth.mjs';
import util from '../util.js';
import BusinessBase from './business-base.mjs';
import nodemailer from "nodemailer";
import dayjs from 'dayjs';
import crypto from 'crypto';

const authMethods = {
    basicAuth: () => new BasicAuth(),
    entraIdAuth: () => new EntraIdAuth(),
    ldapAuth: () => new LdapAuth()
};

class Auth {
    /**
     * Authorises a user using the specified method.
     * @param {{ username: string, password: string, methodKey?: string, req: any, res: any, next: any }} params - The parameters.
     * @returns {Promise<object>} - The authorisation result.
     * @throws {Error} - If the authorisation fails.
     */
    async authorise({ username, password, methodKey = "basicAuth", req, res, next }) {

        const authMethod = authMethods[methodKey]();

        try {
            const user = await authMethod.authenticate({ username, password, req, res, next });
            if (!user || !user?.success) {
                return {
                    success: false,
                    message: `Invalid username or password`
                };
            }
            return { ...user };
        } catch (error) {
            return {
                success: false,
                message: error.message || "Invalid username or password"
            };
        }
    }

    /**
     * Retrieves the configuration for Microsoft Authentication Library (MSAL)
     * @param {{ req: any, res: any, next: any }} params - The parameters.
     * @returns {Promise<object>} - The MSAL configuration.
     * @throws {Error} - If there is an error retrieving the configuration.
     */
    async getRedirectToAuthUrl(req) {
        const entraIdAuth = new EntraIdAuth();
        try {
            return await entraIdAuth.getRedirectToAuthUrl(req);
        } catch (error) {
            return {
                success: false,
                message: error.message || "Invalid username or password"
            };
        }
    }

    /**
     * Retrieves the configuration for Microsoft Authentication Library (MSAL) using the EntraID service.
     * @param {{ req: any, res: any, next: any }} params - The parameters.
     * @returns {Promise<object>} - The MSAL configuration.
     * @throws {Error} - If there is an error retrieving the configuration.
     */
    async getEntraLogin(req) {
        const entraIdAuth = new EntraIdAuth();
        try {
            return await entraIdAuth.entraLogin(req);
        } catch (error) {
            return {
                success: false,
                message: error.message || "token mismatch or session expired"
            };
        }
    }

    generateOTP() {
        const digits = '0123456789';
        let OTP = '';
        for (let i = 0; i < 6; i++) {
            OTP += digits[Math.floor(Math.random() * 10)];
        }
        return OTP;
    }

    async sendEmail({ userInfo, template, subject, replaceTags }) {
        const transporter = nodemailer.createTransport({
            host: "mail.stream4tech.app",
            port: 587,
            secure: false,
            auth: {
                user: "apps@stream4tech.app",
                pass: "Q[,cV&J!K7XX+gH4c<"
            },
            tls: {
                rejectUnauthorized: false
            }
        });
        const htmlContent = replaceTags ? template.replace('${userInfo.tags.OTP}', userInfo.tags.OTP) : template;
        const mailOptions = {
            from: 'apps@stream4tech.app',
            to: userInfo.EmailAddress,
            subject: subject,
            html: htmlContent
        };
        try {
            await transporter.sendMail(mailOptions);
            return;
        } catch (error) {
            return { error: error.message, success: false, message: "Email_Failed" };
        }
    }

    async recoverPassword({ req, res, template }) {
        const { email, tokenKey, newPassword } = { ...req.body.formData, ...req.query, ...req.params };
        let response = { success: false };
        const superAdministratorRoleId = await BusinessBase.businessObject.sql.query(`SELECT * FROM Security_Role WHERE Name = '${util.superAdmin}'`);
        const formattedTokenExpire = dayjs.utc().format('YYYY-MM-DDTHH:mm:ss');
        const formattedModifiedOn = dayjs(new Date()).format('YYYY-MM-DDTHH:mm:ss');

        if (email) {
            const userData = await BusinessBase.businessObject.sql.query(`SELECT * FROM Security_User WHERE EmailAddress = '${email}'`);
            if (!userData) {
                response.success = false
                response.info = "NoUserFound"
                // preventing user with superAdmin user role from being changed
            } else if (userData[0].RoleId.toString() === superAdministratorRoleId[0].RoleId.toString()) {
                response.success = false
                response.info = "Password cannot be changed for this user"
            }
            else {
                if (!tokenKey) {
                    if (!userData[0].IsActive) {
                        response.success = false
                    }
                    else {
                        const userName = userData[0].Username;
                        const generatedOTP = this.generateOTP();
                        await BusinessBase.businessObject.sql.query(`UPDATE Security_User SET Token = ${generatedOTP}, TokenExpire = '${formattedTokenExpire}', ModifiedOn = '${formattedModifiedOn}' WHERE EmailAddress = '${userData[0].EmailAddress}'`);
                        const mailTags = { OTP: generatedOTP }
                        const userInfo = { UserName: userName, EmailAddress: userData[0].EmailAddress, tags: mailTags }
                        await this.sendEmail({ userInfo, template: template[0], subject: 'OTP For ForgotPassword', replaceTags: true });
                        response = {
                            success: true,
                            info: 'OTP has been sent'
                        }
                    }
                }
                else {
                    const user = await BusinessBase.businessObject.sql.query(`SELECT * FROM Security_User WHERE EmailAddress = '${email}' AND Token = ${parseInt(tokenKey)}`);
                    if (user[0] && newPassword && email) {
                        const tokenExpiry = user[0].TokenExpire;
                        const currentTime = dayjs();
                        const updatedTokenExpiry = dayjs(tokenExpiry).add(20, 'minute');
                        // Compare the two times
                        if (!updatedTokenExpiry.isAfter(currentTime)) {
                            response = {
                                data: [],
                                success: false,
                                info: "Token has expired"
                            }
                            return res.status(200).json(response);
                        }
                        const updatedPassword = crypto.createHash('sha1').update(newPassword || "").digest('hex');
                        await BusinessBase.businessObject.sql.query(`UPDATE Security_User SET Token = 0, PasswordHash = '${updatedPassword}' WHERE EmailAddress = '${email}'`);
                        // const templateId = consts.EmailTemplate.ChangePasswordSuccessfully;
                        const mailTags = { Username: userData[0].Username, Password: newPassword }
                        const userInfo = { EmailAddress: userData[0].EmailAddress, tags: mailTags }
                        await this.sendEmail({userInfo, template: template[1], subject: 'Password Changed', replaceTags: false});
                        response = {
                            data: [],
                            success: true,
                            info: "Password changed successfully"
                        }
                    }
                    else {
                        response = {
                            data: [],
                            success: false,
                            info: 'Invalid Token Key'
                        }
                    }
                }
            }
            res.status(200).json(response);
        }
        else {
            response = {
                success: false,
                info: 'Invalid Token Key'
            }
        }
    }
}

export default Auth;