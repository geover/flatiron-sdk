const SHA1 = require("crypto-js/sha1");
const SHA256 = require("crypto-js/sha256");
const MD5 = require("crypto-js/md5");

require("isomorphic-fetch");

module.exports = class FlatIronCyber {
  constructor(apiKey) {
    this.apiKey = apiKey || null;
    this.endpoint =
      "https://wl7r41nzm9.execute-api.us-east-1.amazonaws.com/staging/check";
  }

  async check(email, password) {
    // sanitize
    if (typeof email === "string" && email !== "") {
      email = email.trim();
    }

    // validate
    if (email === null) {
      return { message: "Invalid email", success: false };
    }
    if (password === null) {
      return { message: "Invalid password", success: false };
    }
    if (this.apiKey === null) {
      return { message: "Invalid API key", success: false };
    }

    // prep data
    const payload = {
      email,
      password: {
        SHA1: SHA1(password).toString(),
        SHA256: SHA256(password).toString(),
        MD5: MD5(password).toString(),
      },
    };
    const options = {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
    };

    let response;
    try {
      response = await fetch(this.endpoint, options);
    } catch (error) {
      response = null;
    }

    if (response === null) {
      return {
        success: false,
        message: "Unknown error occured!",
      };
    }

    return await response.json();
  }

  setApiKey(apiKey) {
    this.apiKey = apiKey;
  }
};
