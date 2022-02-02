const crypto = require('crypto');

/**
 * `TelegramStrategy` constructor.
 *
 * The Telegram authentication strategy authenticates requests by delegating to
 * Telegram using their protocol: https://core.telegram.org/widgets/login
 *
 * Applications must supply a `verify` callback which accepts an `account` object,
 * and then calls `done` callback sypplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * More info here: https://core.telegram.org/widgets/login
 *
 * @param {Object} options
 * @param {Function} verify
 * @example
 * passport.use(
 *   new TelegramStrategy({ botId: 12434151 }),
 *   (user) => { User.findOrCreate({ telegramId: user.id }, done); }
 * );
 */

module.exports = class Strategy {
  name = 'telegram';

  /**
   * @param {Object} options
   * @param {Function} verify
   */
  constructor(options, verify) {
    if (!options.botToken) {
      throw new TypeError('options.botToken is required in TelegramStrategy');
    }
    if (!verify) {
      throw new TypeError('TelegramStrategy requires a verify callback');
    }

    this.options = {
      queryExpiration: 86400,
      passReqToCallback: false,
      ...options,
    };

    this.verify = async (...params) => (
      new Promise((resolve, reject) => {
        verify(...params, (err, user, info) => {
          if (err) {
            reject(err);
          } else {
            resolve([user, info]);
          }
        });
      })
    );

    this.hashedBotToken = crypto.createHash('sha256').update(this.options.botToken).digest();
  }

  /**
   * @param {express.Request}
   */
  async authenticate(req) {
    const query = req.method === 'GET' ? req.query : req.body;

    try {
      if (!this.validateQuery(query)) {
        return;
      }

      let result = [];
      if (this.options.passReqToCallback) {
        result = await this.verify(req, query);
      } else {
        result = await this.verify(query);
      }

      const [user, info] = result;

      if (!user) {
        this.fail(info);
        return;
      }

      this.success(user, info);
    } catch (e) {
      this.error(e);
    }
  }

  /**
   * @param {Object} query
   * @returns {boolean}
   */
  validateQuery(query) {
    if (!query.auth_date || !query.hash || !query.id) {
      this.fail({ message: 'Missing some important data' }, 400);
      return false;
    }

    if (!this.isAlive(query)) {
      this.fail({ message: 'Data is outdated' }, 400);
      return false;
    }

    if (!this.hasValidSignature(query)) {
      this.fail({ message: 'Hash validation failed' }, 403);
      return false;
    }

    return true;
  }

  /**
   * @param {Object} query
   * @returns {boolean}
   */
  isAlive(query) {
    const authDate = Number(query.auth_date);

    if (this.options.queryExpiration === -1) {
      return true;
    }

    if (Number.isNaN(authDate)) {
      return false;
    }

    return Math.round(Date.now() / 1000) - authDate <= this.options.queryExpiration;
  }

  /**
   * @param {Object} query
   * @returns {boolean}
   */
  hasValidSignature(query) {
    const allowedFields = ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date'];

    const hashString = Object.keys(query)
      .filter((key) => allowedFields.includes(key))
      .sort()
      .map((key) => `${key}=${query[key]}`)
      .join('\n');

    const hash = crypto.createHmac('sha256', this.hashedBotToken)
      .update(hashString)
      .digest('hex');

    return query.hash === hash;
  }
};
