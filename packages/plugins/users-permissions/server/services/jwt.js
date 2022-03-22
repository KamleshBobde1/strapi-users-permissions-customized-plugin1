'use strict';

/**
 * Jwt.js service
 *
 * @description: A set of functions similar to controller's actions to avoid code duplication.
 */

const _ = require('lodash');
const jwt = require('jsonwebtoken');
// const user = require('@strapi/plugin-users-permissions/server/services/user');

//PBCS-16
const Keycloak = require("keycloak-verify").default;
require("regenerator-runtime");

//PBCS-16
const kcConfigObj = {
  realm: 'entando',
  authServerUrl: 'http://192.168.43.3.nip.io'
}

module.exports = ({ strapi }) => ({

  //PBCS-16 --- code changes in existing method
  getToken(ctx) {
    let token;
    let parts; //--PBCS-16

    if (ctx.request && ctx.request.header && ctx.request.header.authorization) {
      // const parts = ctx.request.header.authorization.split(/\s+/);
      parts = ctx.request.header.authorization.split(/\s+/); //PBCS-16---declared variable out of the block

      if (parts[0].toLowerCase() !== 'bearer' && parts[0].toLowerCase() !== 'entkctoken' || parts.length !== 2) {
        return null;
      }

      token = parts[1];
    } else {
      return null;
    }

    // Existing code
    // return this.verify(token);

    // PBCS-16-----------code to ckeck bearer or entkctoken
    if(parts && parts[0] && parts[0].toLowerCase() === 'bearer') {
      return this.verify(token);
    } else {
      return this.verifyKcToken(token);
    }
    // ------------
  },

  issue(payload, jwtOptions = {}) {
    _.defaults(jwtOptions, strapi.config.get('plugin.users-permissions.jwt'));
    return jwt.sign(
      _.clone(payload.toJSON ? payload.toJSON() : payload),
      strapi.config.get('plugin.users-permissions.jwtSecret'),
      jwtOptions
    );
  },

  verify(token) {
    return new Promise(function(resolve, reject) {
      console.log('strapi.config.get(plugin.users-permissions.jwtSecret): ', strapi.config.get('plugin.users-permissions.jwtSecret'));
      jwt.verify(token, strapi.config.get('plugin.users-permissions.jwtSecret'), {}, function(
        err,
        tokenPayload = {}
      ) {
        if (err) {
          return reject(new Error('Invalid token.'));
        }
        resolve(tokenPayload);
      });
    });
  },

  //new method to decode kc token (end user request) ----- PBCS-16
  async verifyKcToken(token) {
    let kcSuccessResponse = null;
    const config = { realm: kcConfigObj.realm, authServerUrl: kcConfigObj.authServerUrl };
        const keycloak = Keycloak(config);
        await keycloak.verifyOnline(token)
        .then(user => {
          kcSuccessResponse = user;
          console.log('verified user: ', kcSuccessResponse);
        }).catch(e => {
          console.log('kc token verify errrorr: ', e);
          return reject(new Error('Invalid token.'));
        });
        return kcSuccessResponse;
  },
  
});
