const { createClient } = require('redis');

class MemoryCache {
  constructor() {
    this.store = new Map();
  }

  async get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key, value, ttlSeconds = null) {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
    this.store.set(key, { value, expiresAt });
  }

  async incr(key, ttlSeconds = 60) {
    const current = Number((await this.get(key)) || 0) + 1;
    await this.set(key, String(current), ttlSeconds);
    return current;
  }
}

async function createCache() {
  if (!process.env.REDIS_URL) {
    return { cache: new MemoryCache(), connected: false };
  }

  const client = createClient({ url: process.env.REDIS_URL, socket: { reconnectStrategy: () => 500 } });
  client.on('error', () => {});

  try {
    await client.connect();
    return {
      connected: true,
      cache: {
        get: async (key) => client.get(key),
        set: async (key, value, ttlSeconds = null) => {
          if (ttlSeconds) await client.set(key, value, { EX: ttlSeconds });
          else await client.set(key, value);
        },
        incr: async (key, ttlSeconds = 60) => {
          const count = await client.incr(key);
          if (count === 1) await client.expire(key, ttlSeconds);
          return count;
        }
      },
      close: () => client.quit()
    };
  } catch {
    return { cache: new MemoryCache(), connected: false };
  }
}

module.exports = { createCache };
