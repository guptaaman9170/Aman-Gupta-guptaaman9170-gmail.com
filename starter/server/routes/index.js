import * as orgs from './orgs.js';
import * as invites from './invites.js';
import * as devices from './devices.js';

export function registerRoutes(router, deps) {
  orgs.register(router, deps);
  invites.register(router, deps);
  devices.register(router, deps);
}
