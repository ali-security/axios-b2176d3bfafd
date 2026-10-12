import platform from './node/index.js';

const hasBrowserEnv = typeof window !== 'undefined' && typeof document !== 'undefined';

const origin = hasBrowserEnv && window.location.href || 'http://localhost';

export default {
  hasBrowserEnv,
  origin,
  ...platform
}
