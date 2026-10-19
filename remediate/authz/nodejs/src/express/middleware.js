'use strict';

const { ResourceOperation } = require('../interfaces');
const { KomainuSecurityService } = require('../service');

const defaultService = new KomainuSecurityService();

/**
 * Express middleware for declarative object ownership checks.
 *
 * @param {Object} config
 * @param {string} [config.operation=ResourceOperation.READ]
 * @param {string} [config.idParamName='id']
 * @param {Function} config.resourceLoader - (id, req) => Promise<any>
 * @param {KomainuSecurityService} [config.securityService]
 */
function komainuOwnershipMiddleware(config) {
  const op = config.operation || ResourceOperation.READ;
  const idParam = config.idParamName || 'id';
  const loader = config.resourceLoader;
  const service = config.securityService || defaultService;

  return async function (req, res, next) {
    try {
      const user = req.user;
      if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const resourceId = (req.params && req.params[idParam]) ||
                         (req.query && req.query[idParam]) ||
                         (req.body && req.body[idParam]);

      if (!loader) {
        return res.status(500).json({ message: 'resourceLoader must be specified' });
      }

      const resource = await loader(resourceId, req);
      if (!resource) {
        return res.status(404).json({ message: 'Resource not found' });
      }

      const decision = await service.authorize(user, resource, op);
      if (!decision.succeeded) {
        // Core Invariant: Return 404 to block ID enumeration
        return res.status(404).json({ message: 'Resource not found' });
      }

      req.komainuResource = resource;
      next();
    } catch (err) {
      if (err.status === 404 || err.statusCode === 404) {
        return res.status(404).json({ message: 'Resource not found' });
      }
      return res.status(500).json({ message: err.message || 'Internal error' });
    }
  };
}

module.exports = {
  komainuOwnershipMiddleware,
};
