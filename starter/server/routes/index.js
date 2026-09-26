import * as orgs from './orgs.js';
import * as invites from './invites.js';

export function registerRoutes(router, deps) {
  orgs.register(router, deps);
  invites.register(router, deps);
}
