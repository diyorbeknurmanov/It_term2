const config = require("config");
const jwt = require("jsonwebtoken");

class JwtService {
  constructor(accessKey, refreshKey, accessTime, refreshTime) {
    this.accessKey = accessKey;
    this.refreshKey = refreshKey;
    this.accessTime = accessTime;
    this.refreshTime = refreshTime;
  }

  generateTokens(payload) {
    const accessToken = jwt.sign(payload, this.accessKey, {
      expiresIn: this.accessTime,
    });

    const refreshToken = jwt.sign(payload, this.refreshKey, {
      expiresIn: this.refreshTime,
    });

    return { accessToken, refreshToken };
  }

  async verifyAccessToken(token) {
    return jwt.verify(token, this.accessKey);
  }

  async verifyRefreshToken(token) {
    return jwt.verify(token, this.refreshKey);
  }
}

let adminjwtservice = new JwtService(
  config.get("access_key"),
  config.get("refresh_key"),
  config.get("access_time"),
  config.get("refresh_time")
);

let userjwtservice = new JwtService(
  config.get("useraccess_key"),
  config.get("userrefresh_key"),
  config.get("useraccess_time"),
  config.get("userrefresh_time")
);

module.exports = {
  adminjwtservice,
  userjwtservice,
};
