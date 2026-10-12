"use strict";

import assert from "assert";
import http from "http";
import stream from "stream";
import EventEmitter from "events";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import httpAdapter from "../../../lib/adapters/http.js";
import axios from "../../../index.js";
import defaults from "../../../lib/defaults/index.js";

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.validateStatus;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  describe('GHSA-w9j2-pvgh-6h63 validateStatus merge', function () {
    it('should not inherit a polluted validateStatus during mergeConfig', function () {
      Object.prototype.validateStatus = () => true;
      const merged = mergeConfig(defaults, { url: '/x' });
      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
    });

    it('should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted', async function () {
      this.timeout(10000);
      Object.prototype.validateStatus = () => true;
      const server = http.createServer((req, res) => {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end('{"error":"unauthorized"}');
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const { port } = server.address();
      try {
        let threw = false;
        try { await axios.get(`http://127.0.0.1:${port}/`); } catch (err) { threw = true; assert.strictEqual(err.response.status, 401); }
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });
  });

});

describe("GHSA-7q8q-rj6j-mhjq / GHSA-mmx7-hfxf-jppx nested option and config gadgets", function () {
  const pollutedKeys = [
    "username",
    "password",
    "serialize",
    "encode",
    "data",
    "auth",
    "proxy",
    "params",
    "paramsSerializer",
    "transport",
  ];

  // Inject a value onto Object.prototype the way a separate prototype-pollution
  // bug would. `writable: true` keeps ordinary assignments (`obj.data = x`) on
  // plain objects working while the pollution is active.
  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      writable: true,
      configurable: true,
    });
  }

  function cleanup() {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
    delete Object.prototype[Symbol.iterator];
    delete Object.prototype[Symbol.toStringTag];
  }

  function startServer(handler) {
    return new Promise(function (resolve, reject) {
      const server = http.createServer(handler);
      server.once("error", reject);
      server.listen(0, "127.0.0.1", function () {
        resolve(server);
      });
    });
  }

  function stopServer(server) {
    return new Promise(function (resolve) {
      if (!server) {
        return resolve();
      }
      server.close(function () {
        resolve();
      });
    });
  }

  function echoServer() {
    return startServer(function (req, res) {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          authorization: req.headers.authorization || null,
          url: req.url,
        }),
      );
    });
  }

  function withoutProxyEnv(fn) {
    const proxyEnvKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"];
    const originalProxyEnv = Object.create(null);

    proxyEnvKeys.forEach(function (key) {
      originalProxyEnv[key] = process.env[key];
      delete process.env[key];
    });

    return Promise.resolve()
      .then(fn)
      .then(
        function (result) {
          restore();
          return result;
        },
        function (err) {
          restore();
          throw err;
        },
      );

    function restore() {
      proxyEnvKeys.forEach(function (key) {
        if (originalProxyEnv[key] === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = originalProxyEnv[key];
        }
      });
    }
  }

  function stubAdapter(onConfig) {
    return function (config) {
      onConfig(config);

      return Promise.resolve({
        data: null,
        status: 200,
        statusText: "OK",
        headers: {},
        config: config,
        request: {},
      });
    };
  }

  afterEach(cleanup);

  describe("utils", function () {
    it("getSafeProp should ignore values injected onto Object.prototype", function () {
      pollute("username", "inherited-user");

      class Credentials {
        get username() {
          return "from-class";
        }
      }

      assert.strictEqual(utils.getSafeProp({}, "username"), undefined);
      assert.strictEqual(utils.hasOwnInPrototypeChain({}, "username"), false);
      assert.strictEqual(utils.getSafeProp({ username: "own" }, "username"), "own");
      assert.strictEqual(
        utils.getSafeProp(Object.create({ username: "template" }), "username"),
        "template",
      );
      assert.strictEqual(utils.getSafeProp(new Credentials(), "username"), "from-class");
      assert.strictEqual(utils.getSafeProp(null, "username"), undefined);
      assert.strictEqual(utils.getSafeProp(undefined, "username"), undefined);
    });

    it("should ignore inherited symbol properties when validating plain Object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
      };
      Object.prototype[Symbol.toStringTag] = "Custom";

      assert.strictEqual(utils.isPlainObject({}), true);
      assert.strictEqual(utils.isPlainObject(Object.create(null)), true);
      assert.strictEqual(utils.isPlainObject([]), false);
      assert.strictEqual(
        utils.isPlainObject({
          [Symbol.iterator]: function* () {
            yield ["x-own", "yes"];
          },
        }),
        false,
      );
      assert.strictEqual(utils.isPlainObject({ [Symbol.toStringTag]: "Custom" }), false);
    });

    it("should treat an object with a genuinely inherited iterator as non-plain", function () {
      const proto = Object.create(null);
      proto[Symbol.iterator] = function* () {
        yield ["x", "1"];
      };

      assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
    });

    it("should not read polluted Object.prototype iterator accessors for safe iterable checks", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get() {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      assert.strictEqual(utils.isSafeIterable({}), false);
      assert.strictEqual(utils.isPlainObject({}), true);
      assert.strictEqual(accessed, false);
      assert.strictEqual(utils.isSafeIterable([]), true);
      assert.strictEqual(utils.isSafeIterable(new Map()), true);
    });

    it("should stop safe prototype-chain reads on cyclic Proxy prototypes", function () {
      let calls = 0;
      let proxy;
      proxy = new Proxy(
        {},
        {
          getPrototypeOf() {
            calls += 1;
            if (calls > 5) {
              throw new Error("cycled");
            }
            return proxy;
          },
        },
      );

      assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, "missing"), false);
      assert.strictEqual(utils.getSafeProp(proxy, "missing"), undefined);
      assert.ok(calls <= 2, "prototype walk should stop on a cycle, got " + calls + " calls");
    });
  });

  describe("buildURL / getUri", function () {
    it("should ignore inherited serializer options", function () {
      let serializeInvoked = false;
      let encodeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });
      pollute("encode", function () {
        encodeInvoked = true;
        return "inherited";
      });

      assert.strictEqual(buildURL("/foo", { value: "a b" }, {}), "/foo?value=a+b");
      assert.strictEqual(buildURL("/foo", { value: "a b" }), "/foo?value=a+b");
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    });

    it("should still honor own serializer options", function () {
      pollute("serialize", function () {
        return "inherited=1";
      });

      assert.strictEqual(
        buildURL("/foo", { value: "a b" }, {
          serialize: function () {
            return "own=1";
          },
        }),
        "/foo?own=1",
      );
      assert.strictEqual(
        buildURL("/foo", { value: "a b" }, {
          encode: function () {
            return "x";
          },
        }),
        "/foo?x=x",
      );
    });

    it("should ignore inherited nested serializer fields in getUri", function () {
      let serializeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });

      assert.strictEqual(
        axios.getUri({
          url: "/foo",
          params: { value: "a b" },
          paramsSerializer: {},
        }),
        "/foo?value=a+b",
      );
      assert.strictEqual(serializeInvoked, false);
    });

    it("should ignore an inherited paramsSerializer object and params in getUri", function () {
      let serializeInvoked = false;

      pollute("paramsSerializer", {
        serialize: function () {
          serializeInvoked = true;
          return "inherited=1";
        },
      });

      assert.strictEqual(
        axios.getUri({
          url: "/foo",
          params: { value: "a b" },
        }),
        "/foo?value=a+b",
      );
      assert.strictEqual(serializeInvoked, false);

      cleanup();
      pollute("params", { injected: "yes" });

      assert.strictEqual(axios.getUri({ url: "/foo" }), "/foo");
    });
  });

  describe("Axios method aliases / request data", function () {
    it("should ignore inherited data for bodyless method helpers", function () {
      pollute("data", "inherited-body");

      return Promise.all(
        ["delete", "get", "head", "options"].map(function (method) {
          let seenData = "unset";

          return axios[method]("/test", {
            adapter: stubAdapter(function (config) {
              seenData = config.data;
            }),
          }).then(function () {
            assert.strictEqual(seenData, undefined, method + " sent an inherited body");
          });
        }),
      );
    });

    it("should still send own data for bodyless method helpers", function () {
      pollute("data", "inherited-body");

      let seenData;

      return axios
        .delete("/test", {
          data: "own-body",
          adapter: stubAdapter(function (config) {
            seenData = config.data;
          }),
        })
        .then(function () {
          assert.strictEqual(seenData, "own-body");
        });
    });

    it("should not materialize inherited data through transformRequest", function () {
      pollute("data", "inherited-body");

      let seenData = "unset";

      return axios
        .request({
          url: "/test",
          method: "post",
          adapter: stubAdapter(function (config) {
            seenData = config.data;
          }),
        })
        .then(function () {
          assert.strictEqual(seenData, undefined);
        });
    });
  });

  describe("AxiosHeaders", function () {
    it("should not use inherited Symbol.iterator as a key-value source object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-app", "changed"];
        yield ["x-injected", "yes"];
      };

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(headers.get("x-injected"), undefined);
    });

    it("should not read polluted Object.prototype Symbol.iterator accessors", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get() {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(accessed, false);
    });

    it("should keep plain-object headers when Object.prototype Symbol.toStringTag is polluted", function () {
      Object.prototype[Symbol.toStringTag] = "Custom";

      const headers = new AxiosHeaders({
        Authorization: "Bearer VALID",
      });

      assert.strictEqual(headers.get("authorization"), "Bearer VALID");
    });

    it("should not consume an inherited Symbol.iterator for non-plain header sources", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
        yield ["authorization", "Bearer CHANGED"];
      };

      class HeaderBag {
        constructor() {
          this["authorization"] = "Bearer VALID";
        }
      }

      const fromClass = new AxiosHeaders(new HeaderBag());
      assert.strictEqual(fromClass.get("x-injected"), undefined);
      assert.notStrictEqual(fromClass.get("authorization"), "Bearer CHANGED");

      const created = Object.create({ "x-app": "safe" });
      created["authorization"] = "Bearer VALID";
      const fromCreate = new AxiosHeaders(created);
      assert.strictEqual(fromCreate.get("x-injected"), undefined);
      assert.notStrictEqual(fromCreate.get("authorization"), "Bearer CHANGED");
    });
  });

  describe("http adapter", function () {
    it("should ignore inherited nested auth and paramsSerializer fields", async function () {
      const server = await echoServer();

      pollute("username", "inherited-user");
      pollute("password", "inherited-pass");
      pollute("serialize", function () {
        return "inherited=1";
      });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            auth: {},
            params: { value: "a b" },
            paramsSerializer: {},
          },
        );

        assert.deepStrictEqual(response.data, {
          authorization: "Basic Og==",
          url: "/demo?value=a+b",
        });
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should still send own nested auth fields", async function () {
      const server = await echoServer();

      pollute("password", "inherited-pass");

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            auth: { username: "user" },
          },
        );

        assert.strictEqual(
          response.data.authorization,
          "Basic " + Buffer.from("user:").toString("base64"),
        );
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore an inherited auth object", async function () {
      const server = await echoServer();

      pollute("auth", { username: "attacker", password: "exfil" });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
        );

        assert.strictEqual(response.data.authorization, null);
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore an inherited paramsSerializer function", async function () {
      const server = await echoServer();
      let serializerInvoked = false;

      pollute("paramsSerializer", function () {
        serializerInvoked = true;
        return "inherited=1";
      });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          {
            params: { value: "a b" },
          },
        );

        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(response.data.url, "/demo?value=a+b");
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore inherited proxy when http adapter receives a plain config", function () {
      let proxyServer;
      let target;
      let proxyHits = 0;
      let targetHits = 0;

      return withoutProxyEnv(async function () {
        try {
          proxyServer = await startServer(function (req, res) {
            proxyHits += 1;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ via: "proxy", url: req.url }));
          });

          target = await startServer(function (req, res) {
            targetHits += 1;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ via: "target", url: req.url }));
          });

          pollute("proxy", {
            protocol: "http",
            host: "127.0.0.1",
            port: proxyServer.address().port,
          });

          const response = await httpAdapter({
            method: "get",
            url: "http://127.0.0.1:" + target.address().port + "/direct",
            headers: {},
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0,
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(proxyHits, 0);
          assert.strictEqual(targetHits, 1);
          assert.deepStrictEqual(data, { via: "target", url: "/direct" });
        } finally {
          cleanup();
          await stopServer(target);
          await stopServer(proxyServer);
        }
      });
    });

    it("should ignore inherited proxy for requests made through axios", function () {
      let proxyServer;
      let target;
      let proxyHits = 0;
      let targetHits = 0;

      return withoutProxyEnv(async function () {
        try {
          proxyServer = await startServer(function (req, res) {
            proxyHits += 1;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ via: "proxy", url: req.url }));
          });

          target = await startServer(function (req, res) {
            targetHits += 1;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ via: "target", url: req.url }));
          });

          pollute("proxy", {
            protocol: "http",
            host: "127.0.0.1",
            port: proxyServer.address().port,
          });

          const response = await axios.get(
            "http://127.0.0.1:" + target.address().port + "/direct",
          );

          assert.strictEqual(proxyHits, 0);
          assert.strictEqual(targetHits, 1);
          assert.deepStrictEqual(response.data, { via: "target", url: "/direct" });
        } finally {
          cleanup();
          await stopServer(target);
          await stopServer(proxyServer);
        }
      });
    });

    it("should ignore inherited paramsSerializer when http adapter receives a plain config", async function () {
      let server;
      let serializerInvoked = false;

      pollute("paramsSerializer", {
        serialize: function () {
          serializerInvoked = true;
          return "inherited=1";
        },
      });

      try {
        server = await startServer(function (req, res) {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ url: req.url }));
        });

        const response = await httpAdapter({
          method: "get",
          url: "http://127.0.0.1:" + server.address().port + "/direct",
          headers: {},
          params: { value: "a b" },
          proxy: false,
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });
        const data = JSON.parse(response.data);

        assert.strictEqual(serializerInvoked, false);
        assert.deepStrictEqual(data, { url: "/direct?value=a+b" });
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should ignore an inherited transport", async function () {
      const server = await echoServer();
      let transportHijacked = false;

      pollute("transport", {
        request: function () {
          transportHijacked = true;
          throw new Error("polluted transport used");
        },
      });

      try {
        const response = await axios.get(
          "http://127.0.0.1:" + server.address().port + "/demo",
          { proxy: false },
        );

        assert.strictEqual(transportHijacked, false);
        assert.strictEqual(response.data.url, "/demo");
      } finally {
        cleanup();
        await stopServer(server);
      }
    });

    it("should not use inherited Symbol.iterator for request or response headers", async function () {
      let capturedHeaders;
      const stubTransport = {
        request(options, handleResponse) {
          capturedHeaders = Object.assign({}, options.headers);
          const req = new EventEmitter();
          req.write = function () {
            return true;
          };
          req.setTimeout = function () {};
          req.destroy = function () {};
          req.end = function () {
            const res = new stream.Readable({ read() {} });
            res.statusCode = 200;
            res.statusMessage = "OK";
            res.headers = { "x-server": "real" };
            res.rawHeaders = [];
            res.req = req;
            process.nextTick(function () {
              handleResponse(res);
              res.push(null);
            });
          };
          return req;
        },
      };

      try {
        Object.prototype[Symbol.iterator] = function* () {
          yield ["X-Injected", "yes"];
          yield ["Authorization", "Bearer CHANGED"];
        };

        const response = await axios.get("http://stub.invalid/", {
          headers: {
            Authorization: "Bearer VALID_USER_TOKEN",
            "X-App": "safe",
          },
          transport: stubTransport,
          maxRedirects: 0,
        });

        assert.ok(capturedHeaders, "transport was not invoked");
        assert.strictEqual(capturedHeaders["X-App"], "safe");
        assert.strictEqual(
          capturedHeaders.Authorization || capturedHeaders.authorization,
          "Bearer VALID_USER_TOKEN",
        );
        assert.strictEqual(capturedHeaders["X-Injected"] || capturedHeaders["x-injected"], undefined);
        assert.strictEqual(response.headers.get("x-server"), "real");
        assert.strictEqual(response.headers.get("x-injected"), undefined);
      } finally {
        cleanup();
      }
    });
  });
});

describe("GHSA-3w6x-2g7m-8v23 default transform config gadgets", function () {
  const pollutedKeys = [
    "responseType",
    "transitional",
    "formSerializer",
    "env",
    "response",
    "parseReviver",
  ];

  const transformRequest = defaults.transformRequest[0];
  const transformResponse = defaults.transformResponse[0];

  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      writable: true,
      configurable: true,
    });
  }

  function cleanup() {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
  }

  function responseAdapter(body, onConfig) {
    return function (config) {
      if (onConfig) {
        onConfig(config);
      }

      return Promise.resolve({
        data: body,
        status: 200,
        statusText: "OK",
        headers: { "content-type": "application/json" },
        config: config,
        request: {},
      });
    };
  }

  afterEach(cleanup);

  describe("transformResponse", function () {
    it("should ignore an inherited responseType when parsing JSON responses", async function () {
      pollute("responseType", "text");

      const response = await axios.get("http://stub.invalid/api/me", {
        adapter: responseAdapter('{"role":"viewer","isAdmin":false}'),
      });

      assert.strictEqual(typeof response.data, "object");
      assert.strictEqual(response.data.role, "viewer");
      assert.strictEqual(response.data.isAdmin, false);
    });

    it("should ignore an inherited responseType in the default transform", function () {
      pollute("responseType", "text");

      const result = transformResponse.call(
        { transitional: defaults.transitional },
        '{"isAdmin":false}',
      );

      assert.deepStrictEqual(result, { isAdmin: false });
    });

    it("should still honor an own responseType", function () {
      const result = transformResponse.call(
        { transitional: defaults.transitional, responseType: "text" },
        '{"isAdmin":false}',
      );

      assert.strictEqual(result, '{"isAdmin":false}');
    });

    it("should ignore inherited transitional options", function () {
      pollute("transitional", {
        silentJSONParsing: true,
        forcedJSONParsing: false,
        clarifyTimeoutError: false,
      });

      const result = transformResponse.call({}, '{"isAdmin":false}');

      assert.deepStrictEqual(result, { isAdmin: false });
    });

    it("should not turn on strict JSON parsing through inherited transitional options", function () {
      pollute("transitional", {
        silentJSONParsing: false,
        forcedJSONParsing: true,
        clarifyTimeoutError: false,
      });

      const result = transformResponse.call({ responseType: "json" }, "<html>not json</html>");

      assert.strictEqual(result, "<html>not json</html>");
    });

    it("should not attach an inherited response object to JSON parse errors", function () {
      const forged = { status: 200, data: { forged: true } };
      pollute("response", forged);

      assert.throws(
        function () {
          transformResponse.call(
            {
              responseType: "json",
              transitional: {
                silentJSONParsing: false,
                forcedJSONParsing: true,
                clarifyTimeoutError: false,
              },
            },
            "{not json",
          );
        },
        function (err) {
          assert.strictEqual(err.code, "ERR_BAD_RESPONSE");
          assert.strictEqual(Object.prototype.hasOwnProperty.call(err, "response"), false);
          return true;
        },
      );
    });

    it("should not run an inherited parseReviver on JSON responses", async function () {
      let reviverCalled = false;
      pollute("parseReviver", function (key, value) {
        reviverCalled = true;
        if (key === "isAdmin") return true;
        if (key === "role") return "admin";
        return value;
      });

      const response = await axios.get("http://stub.invalid/api/me", {
        adapter: responseAdapter('{"role":"viewer","isAdmin":false}'),
      });

      assert.strictEqual(reviverCalled, false);
      assert.strictEqual(response.data.role, "viewer");
      assert.strictEqual(response.data.isAdmin, false);
    });
  });

  describe("transformRequest", function () {
    function tamperingSerializer() {
      return {
        visitor: function (value, key, path, helpers) {
          if (key === "role") {
            this.append("role", "admin");
            return false;
          }
          return helpers.defaultVisitor.apply(this, arguments);
        },
      };
    }

    it("should ignore an inherited formSerializer for urlencoded requests", async function () {
      let sentData;
      pollute("formSerializer", tamperingSerializer());

      await axios.post(
        "http://stub.invalid/",
        { role: "viewer" },
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          adapter: responseAdapter(null, function (config) {
            sentData = config.data;
          }),
        },
      );

      assert.strictEqual(sentData, "role=viewer");
    });

    it("should ignore an inherited formSerializer in the default transform", function () {
      pollute("formSerializer", tamperingSerializer());

      const result = transformRequest.call(
        {},
        { role: "viewer" },
        new AxiosHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      );

      assert.strictEqual(result, "role=viewer");
    });

    it("should still honor an own formSerializer", async function () {
      let sentData;

      await axios.post(
        "http://stub.invalid/",
        { role: "viewer" },
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          formSerializer: tamperingSerializer(),
          adapter: responseAdapter(null, function (config) {
            sentData = config.data;
          }),
        },
      );

      assert.strictEqual(sentData, "role=admin");
    });

    it("should ignore an inherited env.FormData for multipart requests", function () {
      let constructed = false;

      function EvilFormData() {
        constructed = true;
        this.entries = [];
      }
      EvilFormData.prototype.append = function (key, value) {
        this.entries.push([key, value]);
      };

      pollute("env", { FormData: EvilFormData });

      const result = transformRequest.call(
        {},
        { role: "viewer" },
        new AxiosHeaders({ "Content-Type": "multipart/form-data" }),
      );

      assert.strictEqual(constructed, false);
      assert.ok(!(result instanceof EvilFormData));
    });

    it("should still honor an own env.FormData", function () {
      function OwnFormData() {
        this.entries = [];
      }
      OwnFormData.prototype.append = function (key, value) {
        this.entries.push([key, value]);
      };

      const result = transformRequest.call(
        { env: { FormData: OwnFormData } },
        { role: "viewer" },
        new AxiosHeaders({ "Content-Type": "multipart/form-data" }),
      );

      assert.ok(result instanceof OwnFormData);
      assert.deepStrictEqual(result.entries, [["role", "viewer"]]);
    });
  });
});
