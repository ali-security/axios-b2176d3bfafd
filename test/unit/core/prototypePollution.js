"use strict";

import assert from "assert";
import http from "http";
import stream from "stream";
import EventEmitter from "events";
import vm from "vm";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import httpAdapter from "../../../lib/adapters/http.js";
import axios from "../../../index.js";
import defaults from "../../../lib/defaults/index.js";
import validator from "../../../lib/helpers/validator.js";
import AxiosError from "../../../lib/core/AxiosError.js";

const nodeMajorVersion = parseInt(process.versions.node.split(".")[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.validateStatus;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.transitional;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.env;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.responseType;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.config;
    delete Object.prototype.customOpt;
    delete Object.prototype.transport;
    delete Object.prototype.formSerializer;
    delete Object.prototype.parseReviver;
    delete Object.prototype.createConnection;
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

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
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

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should pass an own inert createConnection option to transports', async function () {
      this.timeout(10000);
      Object.prototype.createConnection = () => {
        throw new Error('unexpected inherited createConnection');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`, {
          transport: {
            request(options, handleResponse) {
              assert.strictEqual(
                Object.prototype.hasOwnProperty.call(options, 'createConnection'),
                true
              );
              assert.strictEqual(options.createConnection, undefined);
              return http.request(options, handleResponse);
            },
          },
        });

        assert.strictEqual(response.data, 'ok');
      } finally {
        await stopServer(server);
      }
    });

    it('should not let Object.prototype.createConnection hijack the request socket', async function () {
      this.timeout(10000);
      // Node's http.request copies the null-prototype options into an ordinary
      // object and, when no agent is set, opens the socket through
      // `options.createConnection` — an inherited value would take over the
      // connection for both the native and the follow-redirects transports.
      let hijackCalls = 0;
      Object.prototype.createConnection = function polluted() {
        hijackCalls++;
        throw new Error('hijacked connection');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        for (const maxRedirects of [0, 5]) {
          const response = await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects });
          assert.strictEqual(response.data, 'ok');
        }
        assert.strictEqual(hijackCalls, 0, 'polluted createConnection must never be invoked');
      } finally {
        delete Object.prototype.createConnection;
        await stopServer(server);
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  describe('dispatch config compatibility', function () {
    it('should preserve an unchanged merged config through dispatch', async function () {
      let interceptedConfig;
      let adapterConfig;

      const instance = axios.create({
        adapter: async (config) => {
          adapterConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
          };
        },
      });

      instance.interceptors.request.use((config) => {
        interceptedConfig = config;
        return config;
      });

      const response = await instance.get('/config-identity');

      assert.strictEqual(adapterConfig, interceptedConfig);
      assert.strictEqual(response.config, interceptedConfig);
      assert.strictEqual(Object.getPrototypeOf(adapterConfig), null);
      assert.strictEqual(
        Object.prototype.propertyIsEnumerable.call(adapterConfig, 'hasOwnProperty'),
        false
      );
      assert.strictEqual(Object.keys(adapterConfig).includes('hasOwnProperty'), false);
    });

    it('should materialize a frozen null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: 'ok',
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.freeze(Object.assign(Object.create(null), config));
        return replacement;
      });

      const response = await instance.get('/frozen-replacement');

      assert.strictEqual(response.data, 'ok');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.isFrozen(response.config), false);
    });

    it('should filter unsafe keys from a null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: {
            safe: config.safe,
            hasProto: Object.prototype.hasOwnProperty.call(config, '__proto__'),
            hasConstructor: Object.prototype.hasOwnProperty.call(config, 'constructor'),
            hasPrototype: Object.prototype.hasOwnProperty.call(config, 'prototype'),
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.assign(Object.create(null), config);
        replacement.safe = 'preserved';
        Object.defineProperty(replacement, '__proto__', {
          value: 'excluded',
          enumerable: true,
          configurable: true,
          writable: true,
        });
        replacement.constructor = 'excluded';
        replacement.prototype = 'excluded';
        return replacement;
      });

      const response = await instance.get('/unsafe-own-keys');

      assert.deepStrictEqual(response.data, {
        safe: 'preserved',
        hasProto: false,
        hasConstructor: false,
        hasPrototype: false,
      });
      assert.notStrictEqual(response.config, replacement);
    });

    it('should normalize a class-based interceptor replacement', async function () {
      let replacement;

      class ConfigTemplate {
        marker() {
          return 'template';
        }
      }

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.marker(),
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      instance.interceptors.request.use((config) => {
        replacement = new ConfigTemplate();
        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;
        replacement.adapter = config.adapter;
        return replacement;
      });

      const response = await instance.get('/normalized-replacement');

      assert.strictEqual(response.data, 'template');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(response.config instanceof ConfigTemplate, false);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(response.config, 'marker'), true);
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should use GET when the default instance has no own method', async function () {
      Object.prototype.method = 'DELETE';

      const response = await axios({
        url: '/default-method',
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      assert.strictEqual(response.data, 'get');
    });

    it('should ignore headers inherited after a request interceptor replaces config', async function () {
      Object.prototype.headers = { 'X-Injected': 'yes' };

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.headers.get('X-Injected'),
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.headers;
        return replacement;
      });

      const response = await instance.get('/interceptor-headers');

      assert.strictEqual(response.data, undefined);
    });

    it('should ignore behavior inherited after a request interceptor replaces config', async function () {
      let requestTransformCalled = false;
      let responseTransformCalled = false;

      Object.prototype.transformRequest = () => {
        requestTransformCalled = true;
      };
      Object.prototype.transformResponse = () => {
        responseTransformCalled = true;
      };
      Object.prototype.cancelToken = {
        throwIfRequested() {
          throw new Error('unexpected inherited cancelToken');
        },
      };
      Object.prototype.signal = { aborted: true };
      Object.prototype.method = 'delete';

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }),
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.transformRequest;
        delete replacement.transformResponse;
        delete replacement.cancelToken;
        delete replacement.signal;
        delete replacement.method;
        return replacement;
      });

      const response = await instance.get('/interceptor-behavior');

      assert.strictEqual(requestTransformCalled, false);
      assert.strictEqual(responseTransformCalled, false);
      assert.strictEqual(response.data, undefined);
    });

    it('should ignore an adapter inherited after a request interceptor replaces config', async function () {
      let called = false;

      Object.prototype.adapter = async (config) => {
        called = true;
        return {
          data: 'unexpected',
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        };
      };

      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.adapter;
        return replacement;
      });

      const response = await instance.get('data:text/plain;base64,c2FmZQ==', {
        responseType: 'text',
      });

      assert.strictEqual(called, false);
      assert.strictEqual(response.data, 'safe');
    });

    it('should preserve config inherited from a non-shared prototype after interception', async function () {
      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = Object.create({
          adapter: async (resolvedConfig) => ({
            data: resolvedConfig.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config: resolvedConfig,
          }),
          customValue: 'preserved',
        });

        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;

        return replacement;
      });

      const response = await instance.get('/prototype-template');

      assert.strictEqual(response.data, 'preserved');
    });

    [
      ['unchanged', ''],
      ['set to null', 'Object.prototype.constructor = null;'],
      ['deleted', 'delete Object.prototype.constructor;'],
      [
        'replaced by an accessor',
        `Object.defineProperty(Object.prototype, 'constructor', {
          configurable: true,
          get() { return Object; }
        });`,
      ],
    ].forEach(function ([description, mutateConstructor]) {
      it(`should exclude a foreign realm Object.prototype with its constructor ${description}`, async function () {
        const context = vm.createContext({
          adapter: async (config) => ({
            data: config.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
          }),
        });

        const replacement = vm.runInContext(
          `
            Object.prototype.transformResponse = () => 'polluted';
            ${mutateConstructor}
            Object.create({adapter, customValue: 'preserved'});
          `,
          context
        );

        const instance = axios.create();

        instance.interceptors.request.use((config) => {
          replacement.url = config.url;
          replacement.method = config.method;
          replacement.headers = config.headers;

          return replacement;
        });

        const response = await instance.get('/cross-realm-prototype-template');

        assert.strictEqual(response.data, 'preserved');
      });
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });

  // Additional exploit coverage for GHSA-q8qp-cvcw-x6jj: the request options
  // object handed to Node / follow-redirects and its nested beforeRedirects map
  // must not inherit polluted Object.prototype keys, and option validation must
  // not resolve validators through a polluted Object.prototype.
  describe('GHSA-q8qp-cvcw-x6jj request options gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pass a polluted socketPath to http.request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      let capturedValue = 'not-called';
      const origRequest = http.request;
      http.request = function (options) {
        capturedValue = options.socketPath;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`, { maxRedirects: 0 });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, undefined);
    });

    it('should not invoke a polluted Object.prototype.config as a beforeRedirects hook', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.defineProperty(Object.prototype, 'config', {
        value: function polluted() {
          hijackCalled = true;
        },
        writable: true,
        configurable: true,
      });

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/final');
        assert.strictEqual(hijackCalled, false);
      } finally {
        delete Object.prototype.config;
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not use a polluted Object.prototype entry as an option validator', function () {
      Object.prototype.customOpt = 'not-a-function';
      try {
        assert.doesNotThrow(function () {
          validator.assertOptions({ customOpt: 1 }, {}, true);
        });
      } finally {
        delete Object.prototype.customOpt;
      }
    });

    it('should report a polluted-only option as unknown instead of invoking it', function () {
      let invoked = false;
      Object.prototype.customOpt = function polluted() {
        invoked = true;
        return true;
      };
      try {
        assert.throws(function () {
          validator.assertOptions({ customOpt: 1 }, {}, false);
        }, function (err) {
          return err instanceof AxiosError && err.code === AxiosError.ERR_BAD_OPTION;
        });
        assert.strictEqual(invoked, false);
      } finally {
        delete Object.prototype.customOpt;
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

    it("should ignore an iterator inherited from a terminal null-prototype boundary", function () {
      // A terminal application template is indistinguishable from a mutated
      // foreign Object.prototype, so its inherited members fail closed.
      const proto = Object.create(null);
      proto[Symbol.iterator] = function* () {
        yield ["x", "1"];
      };

      const value = Object.create(proto);

      assert.strictEqual(utils.isPlainObject(value), true);
      assert.strictEqual(utils.isSafeIterable(value), false);
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

    it("should stop safe prototype flattening on cyclic Proxy prototypes", function () {
      let calls = 0;
      let proxy;
      proxy = new Proxy(
        {},
        {
          getPrototypeOf() {
            calls += 1;
            if (calls > 1) {
              throw new Error("cycled");
            }
            return proxy;
          },
        },
      );

      assert.deepStrictEqual(Object.keys(utils.toSafeFlatObject(proxy)), []);
      assert.strictEqual(calls, 1);
    });

    it("should preserve null-prototype sources but exclude terminal templates", function () {
      const root = Object.create(null);
      root.own = "preserved";

      assert.strictEqual(utils.getSafeProp(root, "own"), "preserved");
      assert.strictEqual(utils.toSafeFlatObject(root), root);

      const template = Object.create(null);
      template.inherited = "excluded";

      const source = Object.create(template);
      source.own = "preserved";

      assert.strictEqual(utils.getSafeProp(source, "own"), "preserved");
      assert.strictEqual(utils.getSafeProp(source, "inherited"), undefined);

      const flattened = utils.toSafeFlatObject(source);

      assert.strictEqual(flattened.own, "preserved");
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, "inherited"), false);
    });

    it("should materialize immutable null-prototype sources", function () {
      const source = Object.freeze(Object.assign(Object.create(null), { own: "preserved" }));
      const flattened = utils.toSafeFlatObject(source);

      assert.notStrictEqual(flattened, source);
      assert.strictEqual(Object.getPrototypeOf(flattened), null);
      assert.strictEqual(flattened.own, "preserved");
      assert.strictEqual(Object.isFrozen(flattened), false);
    });

    it("should materialize and filter unsafe keys from null-prototype sources", function () {
      const source = Object.create(null);
      source.safe = "preserved";
      Object.defineProperty(source, "__proto__", {
        value: "excluded",
        enumerable: true,
        configurable: true,
        writable: true,
      });
      source.constructor = "excluded";
      source.prototype = "excluded";

      const flattened = utils.toSafeFlatObject(source);

      assert.notStrictEqual(flattened, source);
      assert.strictEqual(flattened.safe, "preserved");
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, "__proto__"), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, "constructor"), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, "prototype"), false);
    });

    it("should exclude symbols inherited from terminal null-prototype templates", function () {
      const behavior = Symbol("behavior");
      const template = Object.create(null);
      template[behavior] = () => "excluded";

      const source = Object.create(template);
      const flattened = utils.toSafeFlatObject(source);

      assert.strictEqual(utils.getSafeProp(source, behavior), undefined);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, behavior), false);
    });

    it("should not flatten members injected onto Object.prototype", function () {
      pollute("data", "polluted");

      const flattened = utils.toSafeFlatObject({ own: "preserved" });

      assert.strictEqual(Object.getPrototypeOf(flattened), null);
      assert.strictEqual(flattened.own, "preserved");
      assert.strictEqual(flattened.data, undefined);
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

// CVE-2026-44495: mergeConfig read config1[prop] / config2[prop] directly, so a
// key that is own on one config but missing from the other was resolved through
// a polluted Object.prototype. The http adapter likewise read config.env.Blob
// without an own-property check when decoding data: URIs.
describe("CVE-2026-44495 mergeConfig and http adapter own-property reads", function () {
  const pollutedKeys = [
    "transformRequest",
    "transformResponse",
    "adapter",
    "transport",
    "headers",
    "baseURL",
    "params",
    "env",
  ];

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

  afterEach(cleanup);

  describe("mergeConfig", function () {
    it("should not let a polluted transformRequest replace an own config1 value", function () {
      const ownTransform = function ownTransform(data) {
        return data;
      };
      pollute("transformRequest", function polluted() {
        return "hijacked";
      });

      const result = mergeConfig({ transformRequest: [ownTransform] }, { url: "/a" });

      assert.ok(Array.isArray(result.transformRequest));
      assert.strictEqual(result.transformRequest.length, 1);
      assert.strictEqual(result.transformRequest[0], ownTransform);
    });

    it("should not let a polluted transformResponse replace an own config1 value", function () {
      const ownTransform = function ownTransform(data) {
        return data;
      };
      pollute("transformResponse", function polluted() {
        return "hijacked";
      });

      const result = mergeConfig({ transformResponse: [ownTransform] }, { url: "/a" });

      assert.ok(Array.isArray(result.transformResponse));
      assert.strictEqual(result.transformResponse.length, 1);
      assert.strictEqual(result.transformResponse[0], ownTransform);
    });

    it("should not let a polluted adapter replace the default adapter", function () {
      pollute("adapter", function pollutedAdapter() {
        return Promise.resolve({ data: "forged", status: 200 });
      });

      const result = mergeConfig(defaults, { url: "/a" });

      assert.deepStrictEqual(result.adapter, defaults.adapter);
    });

    it("should not let a polluted transport replace an own config1 value", function () {
      const ownTransport = { request: function ownRequest() {} };
      pollute("transport", { request: function pollutedRequest() {} });

      const result = mergeConfig({ transport: ownTransport }, { url: "/a" });

      assert.strictEqual(result.transport.request, ownTransport.request);
    });

    it("should not let a polluted baseURL replace an own config1 value", function () {
      pollute("baseURL", "https://attacker.example");

      const result = mergeConfig({ baseURL: "https://api.example.com" }, { url: "/users" });

      assert.strictEqual(result.baseURL, "https://api.example.com");
    });

    it("should not merge polluted headers into own config1 headers", function () {
      pollute("headers", { "X-Injected": "evil" });

      const result = mergeConfig(
        { headers: { common: { Accept: "application/json" } } },
        { url: "/a" },
      );

      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "X-Injected"),
        false,
      );
    });

    it("should not merge a polluted config1 value into an own config2 object", function () {
      pollute("params", { injected: "evil" });

      const result = mergeConfig({}, { params: { q: "1" } });

      assert.deepStrictEqual(Object.keys(result.params), ["q"]);
      assert.strictEqual(result.params.q, "1");
    });

    it("should still prefer own config2 values over own config1 values", function () {
      const first = function first(data) {
        return data;
      };
      const second = function second(data) {
        return data;
      };
      pollute("transformRequest", function polluted() {
        return "hijacked";
      });

      const result = mergeConfig(
        { transformRequest: [first], baseURL: "https://one.example" },
        { transformRequest: [second], url: "/a" },
      );

      assert.deepStrictEqual(result.transformRequest, [second]);
      assert.strictEqual(result.baseURL, "https://one.example");
      assert.strictEqual(result.url, "/a");
    });
  });

  describe("axios.request", function () {
    it("should not run a polluted transformRequest for a plain request config", async function () {
      let invoked = false;
      let sentData;

      pollute("transformRequest", function polluted() {
        invoked = true;
        return "INJECTED";
      });

      await axios.request({
        url: "http://stub.invalid/",
        method: "post",
        data: { hello: "world" },
        adapter: function (config) {
          sentData = config.data;
          return Promise.resolve({
            data: null,
            status: 200,
            statusText: "OK",
            headers: {},
            config: config,
            request: {},
          });
        },
      });

      assert.strictEqual(invoked, false);
      assert.strictEqual(sentData, JSON.stringify({ hello: "world" }));
    });

    it("should not dispatch through a polluted adapter for a plain request config", async function () {
      let invoked = false;

      pollute("adapter", function pollutedAdapter(config) {
        invoked = true;
        return Promise.resolve({
          data: "forged",
          status: 200,
          statusText: "OK",
          headers: {},
          config: config,
          request: {},
        });
      });

      const response = await axios.request({
        url: "data:text/plain;base64," + Buffer.from("genuine").toString("base64"),
        responseType: "text",
      });

      assert.strictEqual(invoked, false);
      assert.strictEqual(response.data, "genuine");
    });
  });

  describe("http adapter", function () {
    function dataURIConfig(extra) {
      return Object.assign(
        {
          method: "get",
          url: "data:application/octet-stream;base64," + Buffer.from("123").toString("base64"),
          headers: {},
          responseType: "blob",
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        },
        extra || {},
      );
    }

    it("should ignore a polluted env.Blob when decoding a data: URI as a blob", async function () {
      let constructed = false;

      function EvilBlob() {
        constructed = true;
      }

      pollute("env", { Blob: EvilBlob });

      let response;
      let error;

      try {
        response = await httpAdapter(dataURIConfig());
      } catch (err) {
        error = err;
      }

      assert.strictEqual(constructed, false);
      assert.ok(!(response && response.data instanceof EvilBlob));

      if (typeof Blob !== "undefined") {
        assert.ok(!error, error && error.message);
        assert.ok(response.data instanceof Blob);
        assert.strictEqual(response.data.type, "application/octet-stream");
      } else {
        // No native Blob: the adapter must refuse instead of using the polluted class.
        assert.ok(error);
      }
    });

    it("should still honor an own env.Blob when decoding a data: URI as a blob", async function () {
      function OwnBlob(parts, options) {
        this.parts = parts;
        this.type = options.type;
      }

      const response = await httpAdapter(dataURIConfig({ env: { Blob: OwnBlob } }));

      assert.ok(response.data instanceof OwnBlob);
      assert.strictEqual(response.data.type, "application/octet-stream");
      assert.strictEqual(Buffer.concat(response.data.parts).toString(), "123");
    });
  });
});

// CVE-2026-44490: a polluted Object.prototype could
//  - turn the data descriptors axios hands to Object.defineProperty into invalid
//    accessor descriptors (Object.prototype.get / set), breaking axios entirely;
//  - surface through utils.merge's read of the existing value (result[key]);
//  - inject header buckets (Object.prototype.common / Object.prototype.<method>)
//    into the flattened request headers;
//  - inject Proxy-Authorization credentials or redirect the proxied request via
//    setProxy's prototype-chain reads of auth / username / password / hostname.
describe("CVE-2026-44490 descriptor, merge, header bucket and proxy gadgets", function () {
  const pollutedKeys = [
    "get",
    "set",
    "headers",
    "customNested",
    "common",
    "options",
    "auth",
    "username",
    "password",
    "hostname",
    "host",
    "port",
    "protocol",
  ];

  function cleanup() {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
  }

  // Pollute Object.prototype only while fn runs synchronously, and always clear
  // it before control returns to mocha. The outcome (result or thrown error) is
  // returned so assertions run against a clean prototype.
  function withPollution(values, fn) {
    Object.keys(values).forEach(function (key) {
      Object.prototype[key] = values[key];
    });

    try {
      return { result: fn() };
    } catch (err) {
      return { error: err };
    } finally {
      cleanup();
    }
  }

  function okResponse(config) {
    return Promise.resolve({
      data: null,
      status: 200,
      statusText: "OK",
      headers: {},
      config: config,
      request: {},
    });
  }

  afterEach(cleanup);

  // Object.defineProperty performs HasProperty/Get for `get` and `set` on the
  // descriptor. A plain-literal descriptor inherits a polluted
  // Object.prototype.get / set and is rejected with a TypeError.
  describe("Object.defineProperty descriptor literals", function () {
    it("should define AxiosHeaders accessors when Object.prototype.get is polluted", function () {
      const outcome = withPollution({ get: "attacker" }, function () {
        AxiosHeaders.accessor("X-Pp-Get-Test");
      });

      assert.ifError(outcome.error);

      const headers = new AxiosHeaders();
      headers.setXPpGetTest("value");
      assert.strictEqual(headers.getXPpGetTest(), "value");
      assert.strictEqual(headers.hasXPpGetTest(), true);
    });

    it("should define AxiosHeaders accessors when Object.prototype.set is polluted", function () {
      const outcome = withPollution({ set: "attacker" }, function () {
        AxiosHeaders.accessor("X-Pp-Set-Test");
      });

      assert.ifError(outcome.error);

      const headers = new AxiosHeaders();
      headers.setXPpSetTest("value");
      assert.strictEqual(headers.getXPpSetTest(), "value");
    });

    it("should not throw in mergeConfig when Object.prototype.get is polluted", function () {
      const outcome = withPollution({ get: "attacker" }, function () {
        return mergeConfig({}, { url: "/x", method: "get" });
      });

      assert.ifError(outcome.error);
      assert.strictEqual(outcome.result.url, "/x");
      assert.strictEqual(outcome.result.method, "get");
      assert.strictEqual(typeof outcome.result.hasOwnProperty, "function");
    });

    it("should not throw in mergeConfig when Object.prototype get and set are polluted functions", function () {
      const outcome = withPollution(
        { get: function () {}, set: function () {} },
        function () {
          return mergeConfig(
            {},
            {
              url: "/users",
              headers: {
                common: {
                  Accept: "application/json",
                },
              },
            },
          );
        },
      );

      assert.ifError(outcome.error);
      assert.strictEqual(outcome.result.url, "/users");
      assert.strictEqual(outcome.result.headers.common.Accept, "application/json");
    });

    it("should not throw in utils.extend when Object.prototype.get is polluted", function () {
      const a = {};
      const b = {
        x: 1,
        fn: function () {},
      };

      const outcome = withPollution({ get: "attacker" }, function () {
        utils.extend(a, b);
      });

      assert.ifError(outcome.error);
      assert.strictEqual(a.x, 1);
      assert.strictEqual(typeof a.fn, "function");
    });

    it("should not throw in utils.extend with thisArg when Object.prototype.get is polluted", function () {
      const a = {};
      const ctx = { tag: "ctx" };
      const b = {
        method: function () {
          return this.tag;
        },
      };

      const outcome = withPollution({ get: "attacker" }, function () {
        utils.extend(a, b, ctx);
      });

      assert.ifError(outcome.error);
      assert.strictEqual(a.method(), "ctx");
    });

    it("should not throw in utils.inherits when Object.prototype.get is polluted", function () {
      function Parent() {}
      function Child() {}

      const outcome = withPollution({ get: "attacker" }, function () {
        utils.inherits(Child, Parent);
      });

      assert.ifError(outcome.error);
      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it("should create an instance and dispatch a request when Object.prototype get and set are polluted", async function () {
      let seenHeaders;
      let request;

      const outcome = withPollution(
        { get: function () {}, set: function () {} },
        function () {
          const instance = axios.create({
            adapter: function (config) {
              // The adapter runs synchronously inside the polluted window, so
              // every descriptor site up to dispatch has been exercised by now.
              cleanup();
              seenHeaders = config.headers;
              return okResponse(config);
            },
            headers: {
              common: {
                Accept: "application/json",
              },
            },
          });

          request = instance.get("http://stub.invalid/users");
        },
      );

      assert.ifError(outcome.error);
      await request;
      assert.ok(seenHeaders, "adapter was not invoked");
      assert.strictEqual(seenHeaders.get("Accept"), "application/json");
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe("utils.merge prototype-chain read", function () {
    it("should not pick up polluted Object.prototype.<key> as the existing value", function () {
      const outcome = withPollution({ headers: { evil: "yes" } }, function () {
        return utils.merge({}, { headers: { "Content-Type": "application/json" } });
      });

      assert.ifError(outcome.error);
      assert.strictEqual(outcome.result.headers["Content-Type"], "application/json");
      assert.strictEqual(outcome.result.headers.evil, undefined);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(outcome.result.headers, "evil"),
        false,
      );
    });

    it("should not absorb polluted nested objects when the key is absent from inputs", function () {
      const outcome = withPollution({ customNested: { evil: "yes" } }, function () {
        return utils.merge({}, { safe: "value" });
      });

      assert.ifError(outcome.error);
      assert.strictEqual(outcome.result.safe, "value");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(outcome.result, "customNested"),
        false,
      );
    });

    it("should not copy polluted inherited header buckets into nested headers", function () {
      const outcome = withPollution(
        {
          common: { "x-polluted-common": "yes" },
          get: { "x-polluted-get": "yes" },
        },
        function () {
          return utils.merge(
            {},
            {
              headers: {
                common: {
                  Accept: "application/json",
                },
                get: {
                  "x-own-get": "yes",
                },
              },
            },
          );
        },
      );

      assert.ifError(outcome.error);
      const headers = outcome.result.headers;
      assert.strictEqual(headers.common.Accept, "application/json");
      assert.strictEqual(headers.get["x-own-get"], "yes");
      assert.strictEqual(headers.common["x-polluted-common"], undefined);
      assert.strictEqual(headers.get["x-polluted-get"], undefined);
    });

    it("should not merge a polluted Object.prototype.common into mergeConfig headers", function () {
      const outcome = withPollution({ common: { "x-polluted-common": "yes" } }, function () {
        return mergeConfig(
          { headers: { common: { Accept: "application/json" } } },
          { url: "/a" },
        );
      });

      assert.ifError(outcome.error);
      assert.strictEqual(outcome.result.headers.common.Accept, "application/json");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(outcome.result.headers.common, "x-polluted-common"),
        false,
      );
    });
  });

  // Axios.request flattens headers.common and headers[method] into the request.
  // Those buckets were read through the prototype chain, so a polluted
  // Object.prototype.common / Object.prototype.<method> injected headers.
  describe("Axios.request header bucket flattening", function () {
    function captureAdapter(store) {
      return function (config) {
        cleanup();
        store.headers = config.headers;
        return okResponse(config);
      };
    }

    it("should not send headers from a polluted Object.prototype.common bucket", async function () {
      const store = {};
      const instance = axios.create({ adapter: captureAdapter(store) });
      // Make sure the merged headers carry no own `common` bucket.
      delete instance.defaults.headers.common;

      let request;
      const outcome = withPollution({ common: { "X-Polluted-Common": "yes" } }, function () {
        request = instance.get("http://stub.invalid/", {
          headers: { "X-Request": "request" },
        });
      });

      assert.ifError(outcome.error);
      await request;
      assert.ok(store.headers, "adapter was not invoked");
      assert.strictEqual(store.headers.get("X-Request"), "request");
      assert.strictEqual(store.headers.get("X-Polluted-Common"), undefined);
    });

    it("should not send headers from a polluted Object.prototype.<method> bucket", async function () {
      const store = {};
      const instance = axios.create({ adapter: captureAdapter(store) });

      let request;
      const outcome = withPollution({ options: { "X-Polluted-Options": "yes" } }, function () {
        // The default config has no own `options` bucket, so a request with
        // method OPTIONS would read Object.prototype.options.
        request = instance.request({
          url: "http://stub.invalid/",
          method: "options",
          headers: { "X-Request": "request" },
        });
      });

      assert.ifError(outcome.error);
      await request;
      assert.ok(store.headers, "adapter was not invoked");
      assert.strictEqual(store.headers.get("X-Request"), "request");
      assert.strictEqual(store.headers.get("X-Polluted-Options"), undefined);
    });

    it("should still send headers from own common and method buckets", async function () {
      const store = {};
      const instance = axios.create({
        adapter: captureAdapter(store),
        headers: {
          common: { "X-Own-Common": "c" },
          get: { "X-Own-Get": "g" },
        },
      });

      await instance.get("http://stub.invalid/");

      assert.strictEqual(store.headers.get("X-Own-Common"), "c");
      assert.strictEqual(store.headers.get("X-Own-Get"), "g");
    });
  });

  // End-to-end through the http adapter with a stub transport (no sockets are
  // opened while Object.prototype is polluted). setProxy must only honor own
  // proxy fields.
  describe("http adapter proxy configuration", function () {
    function stubTransport(store) {
      return {
        request(options, handleResponse) {
          // setProxy has already run synchronously by the time the transport is
          // invoked; clear the pollution before any further Node internals run.
          cleanup();
          store.options = {
            hostname: options.hostname,
            host: options.host,
            port: options.port,
            protocol: options.protocol,
            path: options.path,
            headers: Object.assign({}, options.headers),
          };

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
            res.headers = {};
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
    }

    function proxiedGet(store, pollution, proxy) {
      // A fresh instance has no interceptors, so dispatch (and setProxy) runs
      // synchronously inside the polluted window.
      const instance = axios.create();
      let request;
      const outcome = withPollution(pollution, function () {
        request = instance.get("http://stub.invalid/resource", {
          proxy: proxy,
          transport: stubTransport(store),
          maxRedirects: 0,
        });
      });

      assert.ifError(outcome.error);
      return request;
    }

    it("should not inject Proxy-Authorization from a polluted Object.prototype.auth", async function () {
      const store = {};

      await proxiedGet(
        store,
        { auth: { username: "attacker", password: "exfil" } },
        { host: "127.0.0.1", port: 8030, protocol: "http" },
      );

      assert.ok(store.options, "transport was not invoked");
      assert.strictEqual(store.options.hostname, "127.0.0.1");
      assert.strictEqual(store.options.headers["Proxy-Authorization"], undefined);
    });

    it("should not inject Proxy-Authorization from polluted Object.prototype.username and password", async function () {
      const store = {};

      await proxiedGet(
        store,
        { username: "attacker", password: "exfil" },
        { host: "127.0.0.1", port: 8030, protocol: "http" },
      );

      assert.ok(store.options, "transport was not invoked");
      assert.strictEqual(store.options.headers["Proxy-Authorization"], undefined);
    });

    it("should not route the proxied request to a polluted Object.prototype.hostname", async function () {
      const store = {};

      await proxiedGet(
        store,
        { hostname: "attacker.example.com", protocol: "https" },
        { host: "127.0.0.1", port: 8030 },
      );

      assert.ok(store.options, "transport was not invoked");
      assert.strictEqual(store.options.hostname, "127.0.0.1");
      assert.strictEqual(store.options.host, "127.0.0.1");
      assert.strictEqual(store.options.port, 8030);
      assert.strictEqual(store.options.protocol, "http:");
    });

    it("should not complete own proxy auth with a polluted Object.prototype.password", async function () {
      const store = {};

      await proxiedGet(
        store,
        { password: "exfil" },
        { host: "127.0.0.1", port: 8030, auth: { username: "user" } },
      );

      assert.ok(store.options, "transport was not invoked");
      assert.strictEqual(
        store.options.headers["Proxy-Authorization"],
        "Basic " + Buffer.from("user:", "utf8").toString("base64"),
      );
    });

    it("should still send own proxy credentials", async function () {
      const store = {};

      await proxiedGet(
        store,
        {},
        { host: "127.0.0.1", port: 8030, auth: { username: "user", password: "pass" } },
      );

      assert.ok(store.options, "transport was not invoked");
      assert.strictEqual(store.options.hostname, "127.0.0.1");
      assert.strictEqual(
        store.options.headers["Proxy-Authorization"],
        "Basic " + Buffer.from("user:pass", "utf8").toString("base64"),
      );
    });
  });
});
