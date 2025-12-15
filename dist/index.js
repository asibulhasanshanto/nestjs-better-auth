var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/set-cookie-parser/lib/set-cookie.js
var require_set_cookie = __commonJS({
  "node_modules/set-cookie-parser/lib/set-cookie.js"(exports, module) {
    "use strict";
    var defaultParseOptions = {
      decodeValues: true,
      map: false,
      silent: false
    };
    function isNonEmptyString(str) {
      return typeof str === "string" && !!str.trim();
    }
    __name(isNonEmptyString, "isNonEmptyString");
    function parseString(setCookieValue, options) {
      var parts = setCookieValue.split(";").filter(isNonEmptyString);
      var nameValuePairStr = parts.shift();
      var parsed = parseNameValuePair(nameValuePairStr);
      var name = parsed.name;
      var value = parsed.value;
      options = options ? Object.assign({}, defaultParseOptions, options) : defaultParseOptions;
      try {
        value = options.decodeValues ? decodeURIComponent(value) : value;
      } catch (e) {
        console.error("set-cookie-parser encountered an error while decoding a cookie with value '" + value + "'. Set options.decodeValues to false to disable this feature.", e);
      }
      var cookie = {
        name,
        value
      };
      parts.forEach(function(part) {
        var sides = part.split("=");
        var key = sides.shift().trimLeft().toLowerCase();
        var value2 = sides.join("=");
        if (key === "expires") {
          cookie.expires = new Date(value2);
        } else if (key === "max-age") {
          cookie.maxAge = parseInt(value2, 10);
        } else if (key === "secure") {
          cookie.secure = true;
        } else if (key === "httponly") {
          cookie.httpOnly = true;
        } else if (key === "samesite") {
          cookie.sameSite = value2;
        } else if (key === "partitioned") {
          cookie.partitioned = true;
        } else {
          cookie[key] = value2;
        }
      });
      return cookie;
    }
    __name(parseString, "parseString");
    function parseNameValuePair(nameValuePairStr) {
      var name = "";
      var value = "";
      var nameValueArr = nameValuePairStr.split("=");
      if (nameValueArr.length > 1) {
        name = nameValueArr.shift();
        value = nameValueArr.join("=");
      } else {
        value = nameValuePairStr;
      }
      return {
        name,
        value
      };
    }
    __name(parseNameValuePair, "parseNameValuePair");
    function parse4(input, options) {
      options = options ? Object.assign({}, defaultParseOptions, options) : defaultParseOptions;
      if (!input) {
        if (!options.map) {
          return [];
        } else {
          return {};
        }
      }
      if (input.headers) {
        if (typeof input.headers.getSetCookie === "function") {
          input = input.headers.getSetCookie();
        } else if (input.headers["set-cookie"]) {
          input = input.headers["set-cookie"];
        } else {
          var sch = input.headers[Object.keys(input.headers).find(function(key) {
            return key.toLowerCase() === "set-cookie";
          })];
          if (!sch && input.headers.cookie && !options.silent) {
            console.warn("Warning: set-cookie-parser appears to have been called on a request object. It is designed to parse Set-Cookie headers from responses, not Cookie headers from requests. Set the option {silent: true} to suppress this warning.");
          }
          input = sch;
        }
      }
      if (!Array.isArray(input)) {
        input = [
          input
        ];
      }
      if (!options.map) {
        return input.filter(isNonEmptyString).map(function(str) {
          return parseString(str, options);
        });
      } else {
        var cookies = {};
        return input.filter(isNonEmptyString).reduce(function(cookies2, str) {
          var cookie = parseString(str, options);
          cookies2[cookie.name] = cookie;
          return cookies2;
        }, cookies);
      }
    }
    __name(parse4, "parse");
    function splitCookiesString2(cookiesString) {
      if (Array.isArray(cookiesString)) {
        return cookiesString;
      }
      if (typeof cookiesString !== "string") {
        return [];
      }
      var cookiesStrings = [];
      var pos = 0;
      var start;
      var ch;
      var lastComma;
      var nextStart;
      var cookiesSeparatorFound;
      function skipWhitespace() {
        while (pos < cookiesString.length && /\s/.test(cookiesString.charAt(pos))) {
          pos += 1;
        }
        return pos < cookiesString.length;
      }
      __name(skipWhitespace, "skipWhitespace");
      function notSpecialChar() {
        ch = cookiesString.charAt(pos);
        return ch !== "=" && ch !== ";" && ch !== ",";
      }
      __name(notSpecialChar, "notSpecialChar");
      while (pos < cookiesString.length) {
        start = pos;
        cookiesSeparatorFound = false;
        while (skipWhitespace()) {
          ch = cookiesString.charAt(pos);
          if (ch === ",") {
            lastComma = pos;
            pos += 1;
            skipWhitespace();
            nextStart = pos;
            while (pos < cookiesString.length && notSpecialChar()) {
              pos += 1;
            }
            if (pos < cookiesString.length && cookiesString.charAt(pos) === "=") {
              cookiesSeparatorFound = true;
              pos = nextStart;
              cookiesStrings.push(cookiesString.substring(start, lastComma));
              start = pos;
            } else {
              pos = lastComma + 1;
            }
          } else {
            pos += 1;
          }
        }
        if (!cookiesSeparatorFound || pos >= cookiesString.length) {
          cookiesStrings.push(cookiesString.substring(start, cookiesString.length));
        }
      }
      return cookiesStrings;
    }
    __name(splitCookiesString2, "splitCookiesString");
    module.exports = parse4;
    module.exports.parse = parse4;
    module.exports.parseString = parseString;
    module.exports.splitCookiesString = splitCookiesString2;
  }
});

// src/decorators.ts
import { SetMetadata, createParamDecorator } from "@nestjs/common";

// src/symbols.ts
var BEFORE_HOOK_KEY = /* @__PURE__ */ Symbol("BEFORE_HOOK");
var AFTER_HOOK_KEY = /* @__PURE__ */ Symbol("AFTER_HOOK");
var HOOK_KEY = /* @__PURE__ */ Symbol("HOOK");
var AUTH_MODULE_OPTIONS_KEY = /* @__PURE__ */ Symbol("AUTH_MODULE_OPTIONS");

// src/utils.ts
function getRequestFromContext(context) {
  return context.switchToHttp().getRequest();
}
__name(getRequestFromContext, "getRequestFromContext");

// src/decorators.ts
var AllowAnonymous = /* @__PURE__ */ __name(() => SetMetadata("PUBLIC", true), "AllowAnonymous");
var OptionalAuth = /* @__PURE__ */ __name(() => SetMetadata("OPTIONAL", true), "OptionalAuth");
var Roles = /* @__PURE__ */ __name((roles) => SetMetadata("ROLES", roles), "Roles");
var Permissions = /* @__PURE__ */ __name((permissions) => SetMetadata("PERMISSIONS", permissions), "Permissions");
var Public = AllowAnonymous;
var Optional = OptionalAuth;
var Session = createParamDecorator((_data, context) => {
  const request = getRequestFromContext(context);
  return request.session;
});
var BeforeHook = /* @__PURE__ */ __name((path) => SetMetadata(BEFORE_HOOK_KEY, path), "BeforeHook");
var AfterHook = /* @__PURE__ */ __name((path) => SetMetadata(AFTER_HOOK_KEY, path), "AfterHook");
var Hook = /* @__PURE__ */ __name(() => SetMetadata(HOOK_KEY, true), "Hook");

// src/auth-service.ts
import { Inject } from "@nestjs/common";

// src/auth-module-definition.ts
import { ConfigurableModuleBuilder } from "@nestjs/common";
var MODULE_OPTIONS_TOKEN = /* @__PURE__ */ Symbol("AUTH_MODULE_OPTIONS");
var { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } = new ConfigurableModuleBuilder({
  optionsInjectionToken: MODULE_OPTIONS_TOKEN
}).setClassMethodName("forRoot").setExtras({
  isGlobal: true,
  disableTrustedOriginsCors: false,
  disableBodyParser: false,
  disableGlobalAuthGuard: false
}, (def, extras) => {
  return {
    ...def,
    exports: [
      MODULE_OPTIONS_TOKEN
    ],
    global: extras.isGlobal
  };
}).build();

// src/auth-service.ts
function _ts_decorate(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d2;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d2 = decorators[i]) r = (c < 3 ? d2(r) : c > 3 ? d2(target, key, r) : d2(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate, "_ts_decorate");
function _ts_metadata(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata, "_ts_metadata");
function _ts_param(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param, "_ts_param");
var AuthService = class {
  static {
    __name(this, "AuthService");
  }
  options;
  constructor(options) {
    this.options = options;
  }
  /**
  * Returns the API endpoints provided by the auth instance
  */
  get api() {
    return this.options.auth.api;
  }
  /**
  * Returns the complete auth instance
  * Access this for plugin-specific functionality
  */
  get instance() {
    return this.options.auth;
  }
};
AuthService = _ts_decorate([
  _ts_param(0, Inject(MODULE_OPTIONS_TOKEN)),
  _ts_metadata("design:type", Function),
  _ts_metadata("design:paramtypes", [
    typeof AuthModuleOptions === "undefined" ? Object : AuthModuleOptions
  ])
], AuthService);

// src/auth-guard.ts
import { ForbiddenException, Inject as Inject2, Injectable, Optional as Optional2, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

// node_modules/better-call/dist/node.js
var set_cookie_parser = __toESM(require_set_cookie(), 1);
function get_raw_body(req, body_size_limit) {
  const h2 = req.headers;
  if (!h2["content-type"]) return null;
  const content_length = Number(h2["content-length"]);
  if (req.httpVersionMajor === 1 && isNaN(content_length) && h2["transfer-encoding"] == null || content_length === 0) {
    return null;
  }
  let length = content_length;
  if (body_size_limit) {
    if (!length) {
      length = body_size_limit;
    } else if (length > body_size_limit) {
      throw Error(`Received content-length of ${length}, but only accept up to ${body_size_limit} bytes.`);
    }
  }
  if (req.destroyed) {
    const readable = new ReadableStream();
    readable.cancel();
    return readable;
  }
  let size = 0;
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      req.on("error", (error3) => {
        cancelled = true;
        controller.error(error3);
      });
      req.on("end", () => {
        if (cancelled) return;
        controller.close();
      });
      req.on("data", (chunk) => {
        if (cancelled) return;
        size += chunk.length;
        if (size > length) {
          cancelled = true;
          controller.error(new Error(`request body size exceeded ${content_length ? "'content-length'" : "BODY_SIZE_LIMIT"} of ${length}`));
          return;
        }
        controller.enqueue(chunk);
        if (controller.desiredSize === null || controller.desiredSize <= 0) {
          req.pause();
        }
      });
    },
    pull() {
      req.resume();
    },
    cancel(reason) {
      cancelled = true;
      req.destroy(reason);
    }
  });
}
__name(get_raw_body, "get_raw_body");
function getRequest({ request, base, bodySizeLimit }) {
  const baseUrl = request?.baseUrl;
  const fullPath = baseUrl ? baseUrl + request.url : request.url;
  const maybeConsumedReq = request;
  let body = void 0;
  const method = request.method;
  if (method !== "GET" && method !== "HEAD") {
    if (maybeConsumedReq.body !== void 0) {
      const bodyContent = typeof maybeConsumedReq.body === "string" ? maybeConsumedReq.body : JSON.stringify(maybeConsumedReq.body);
      body = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(bodyContent));
          controller.close();
        }
      });
    } else {
      body = get_raw_body(request, bodySizeLimit);
    }
  }
  return new Request(base + fullPath, {
    // @ts-expect-error
    duplex: "half",
    method: request.method,
    body,
    headers: request.headers
  });
}
__name(getRequest, "getRequest");
async function setResponse(res, response) {
  for (const [key, value] of response.headers) {
    try {
      res.setHeader(key, key === "set-cookie" ? set_cookie_parser.splitCookiesString(response.headers.get(key)) : value);
    } catch (error3) {
      res.getHeaderNames().forEach((name) => res.removeHeader(name));
      res.writeHead(500).end(String(error3));
      return;
    }
  }
  res.writeHead(response.status);
  if (!response.body) {
    res.end();
    return;
  }
  if (response.body.locked) {
    res.end("Fatal error: Response body is locked. This can happen when the response was already read (for example through 'response.json()' or 'response.text()').");
    return;
  }
  const reader = response.body.getReader();
  if (res.destroyed) {
    reader.cancel();
    return;
  }
  const cancel = /* @__PURE__ */ __name((error3) => {
    res.off("close", cancel);
    res.off("error", cancel);
    reader.cancel(error3).catch(() => {
    });
    if (error3) res.destroy(error3);
  }, "cancel");
  res.on("close", cancel);
  res.on("error", cancel);
  next();
  async function next() {
    try {
      for (; ; ) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!res.write(value)) {
          res.once("drain", next);
          return;
        }
      }
      res.end();
    } catch (error3) {
      cancel(error3 instanceof Error ? error3 : new Error(String(error3)));
    }
  }
  __name(next, "next");
}
__name(setResponse, "setResponse");
function toNodeHandler(handler) {
  return async (req, res) => {
    const protocol = req.headers["x-forwarded-proto"] || (req.socket.encrypted ? "https" : "http");
    const base = `${protocol}://${req.headers[":authority"] || req.headers.host}`;
    const response = await handler(getRequest({
      base,
      request: req
    }));
    return setResponse(res, response);
  };
}
__name(toNodeHandler, "toNodeHandler");

// node_modules/better-auth/dist/integrations/node.mjs
var toNodeHandler2 = /* @__PURE__ */ __name((auth) => {
  return "handler" in auth ? toNodeHandler(auth.handler) : toNodeHandler(auth);
}, "toNodeHandler");
function fromNodeHeaders(nodeHeaders) {
  const webHeaders = new Headers();
  for (const [key, value] of Object.entries(nodeHeaders)) {
    if (value !== void 0) {
      if (Array.isArray(value)) {
        value.forEach((v) => webHeaders.append(key, v));
      } else {
        webHeaders.set(key, value);
      }
    }
  }
  return webHeaders;
}
__name(fromNodeHeaders, "fromNodeHeaders");

// src/auth-guard.ts
import { WsException } from "@nestjs/websockets";
function _ts_decorate2(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d2;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d2 = decorators[i]) r = (c < 3 ? d2(r) : c > 3 ? d2(target, key, r) : d2(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate2, "_ts_decorate");
function _ts_metadata2(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata2, "_ts_metadata");
function _ts_param2(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param2, "_ts_param");
var AuthContextErrorMap = {
  http: {
    UNAUTHORIZED: /* @__PURE__ */ __name((args) => new UnauthorizedException(args ?? {
      code: "UNAUTHORIZED",
      message: "Unauthorized"
    }), "UNAUTHORIZED"),
    FORBIDDEN: /* @__PURE__ */ __name((args) => new ForbiddenException(args ?? {
      code: "FORBIDDEN",
      message: "Insufficient permissions"
    }), "FORBIDDEN")
  },
  ws: {
    UNAUTHORIZED: /* @__PURE__ */ __name((args) => new WsException(args ?? "UNAUTHORIZED"), "UNAUTHORIZED"),
    FORBIDDEN: /* @__PURE__ */ __name((args) => new WsException(args ?? "FORBIDDEN"), "FORBIDDEN")
  },
  rpc: {
    UNAUTHORIZED: /* @__PURE__ */ __name(() => new Error("UNAUTHORIZED"), "UNAUTHORIZED"),
    FORBIDDEN: /* @__PURE__ */ __name(() => new Error("FORBIDDEN"), "FORBIDDEN")
  }
};
var AuthGuard = class {
  static {
    __name(this, "AuthGuard");
  }
  reflector;
  options;
  permissionService;
  constructor(reflector, options, permissionService) {
    this.reflector = reflector;
    this.options = options;
    this.permissionService = permissionService;
  }
  /**
  * Validates if the current request is authenticated
  * Attaches session and user information to the request object
  * Supports HTTP, GraphQL and WebSocket execution contexts
  * @param context - The execution context of the current request
  * @returns True if the request is authorized to proceed, throws an error otherwise
  */
  async canActivate(context) {
    const request = getRequestFromContext(context);
    const session = await this.options.auth.api.getSession({
      headers: fromNodeHeaders(request.headers || request?.handshake?.headers || [])
    });
    request.session = session;
    request.user = session?.user ?? null;
    const isPublic = this.reflector.getAllAndOverride("PUBLIC", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic) return true;
    const isOptional = this.reflector.getAllAndOverride("OPTIONAL", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isOptional && !session) return true;
    const ctxType = context.getType();
    if (!session) throw AuthContextErrorMap[ctxType].UNAUTHORIZED();
    const requiredPermissions = this.reflector.getAllAndOverride("PERMISSIONS", [
      context.getHandler(),
      context.getClass()
    ]);
    if (requiredPermissions && requiredPermissions.length > 0) {
      if (!this.permissionService) {
        throw new Error("PermissionService is required when using @Permissions() decorator. Please provide a PermissionService implementation.");
      }
      const userId = session.user.id;
      const hasAllPermissions = await this.permissionService.hasAllPermissions(userId, requiredPermissions);
      if (!hasAllPermissions) {
        throw AuthContextErrorMap[ctxType].FORBIDDEN();
      }
    }
    const requiredRoles = this.reflector.getAllAndOverride("ROLES", [
      context.getHandler(),
      context.getClass()
    ]);
    if (requiredRoles && requiredRoles.length > 0) {
      const userRole = session.user.role;
      let hasRole = false;
      if (Array.isArray(userRole)) {
        hasRole = userRole.some((role3) => requiredRoles.includes(role3));
      } else if (typeof userRole === "string") {
        hasRole = userRole.split(",").some((role3) => requiredRoles.includes(role3));
      }
      if (!hasRole) throw AuthContextErrorMap[ctxType].FORBIDDEN();
    }
    return true;
  }
};
AuthGuard = _ts_decorate2([
  Injectable(),
  _ts_param2(0, Inject2(Reflector)),
  _ts_param2(1, Inject2(MODULE_OPTIONS_TOKEN)),
  _ts_param2(2, Optional2()),
  _ts_param2(2, Inject2("PERMISSION_SERVICE")),
  _ts_metadata2("design:type", Function),
  _ts_metadata2("design:paramtypes", [
    typeof Reflector === "undefined" ? Object : Reflector,
    typeof AuthModuleOptions === "undefined" ? Object : AuthModuleOptions,
    typeof IPermissionService === "undefined" ? Object : IPermissionService
  ])
], AuthGuard);

// src/auth-module.ts
import { Inject as Inject3, Logger, Module } from "@nestjs/common";
import { DiscoveryModule, DiscoveryService, HttpAdapterHost, MetadataScanner } from "@nestjs/core";

// node_modules/@better-auth/utils/dist/index.mjs
function getWebcryptoSubtle() {
  const cr = typeof globalThis !== "undefined" && globalThis.crypto;
  if (cr && typeof cr.subtle === "object" && cr.subtle != null)
    return cr.subtle;
  throw new Error("crypto.subtle must be defined");
}
__name(getWebcryptoSubtle, "getWebcryptoSubtle");

// node_modules/better-call/dist/index.js
var __defProp2 = Object.defineProperty;
var __export2 = /* @__PURE__ */ __name((target, all) => {
  for (var name in all) __defProp2(target, name, {
    get: all[name],
    enumerable: true
  });
}, "__export");
function isErrorStackTraceLimitWritable() {
  const desc = Object.getOwnPropertyDescriptor(Error, "stackTraceLimit");
  if (desc === void 0) {
    return Object.isExtensible(Error);
  }
  return Object.prototype.hasOwnProperty.call(desc, "writable") ? desc.writable : desc.set !== void 0;
}
__name(isErrorStackTraceLimitWritable, "isErrorStackTraceLimitWritable");
function hideInternalStackFrames(stack) {
  const lines = stack.split("\n    at ");
  if (lines.length <= 1) {
    return stack;
  }
  lines.splice(1, 1);
  return lines.join("\n    at ");
}
__name(hideInternalStackFrames, "hideInternalStackFrames");
function makeErrorForHideStackFrame(Base, clazz) {
  let HideStackFramesError = class HideStackFramesError extends Base {
    static {
      __name(this, "HideStackFramesError");
    }
    #hiddenStack;
    constructor(...args) {
      if (isErrorStackTraceLimitWritable()) {
        const limit = Error.stackTraceLimit;
        Error.stackTraceLimit = 0;
        super(...args);
        Error.stackTraceLimit = limit;
      } else {
        super(...args);
      }
      const stack = new Error().stack;
      if (stack) {
        this.#hiddenStack = hideInternalStackFrames(stack.replace(/^Error/, this.name));
      }
    }
    // use `getter` here to avoid the stack trace being captured by loggers
    get errorStack() {
      return this.#hiddenStack;
    }
  };
  Object.defineProperty(HideStackFramesError.prototype, "constructor", {
    get() {
      return clazz;
    },
    enumerable: false,
    configurable: true
  });
  return HideStackFramesError;
}
__name(makeErrorForHideStackFrame, "makeErrorForHideStackFrame");
var _statusCode = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  MULTIPLE_CHOICES: 300,
  MOVED_PERMANENTLY: 301,
  FOUND: 302,
  SEE_OTHER: 303,
  NOT_MODIFIED: 304,
  TEMPORARY_REDIRECT: 307,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  PAYMENT_REQUIRED: 402,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  NOT_ACCEPTABLE: 406,
  PROXY_AUTHENTICATION_REQUIRED: 407,
  REQUEST_TIMEOUT: 408,
  CONFLICT: 409,
  GONE: 410,
  LENGTH_REQUIRED: 411,
  PRECONDITION_FAILED: 412,
  PAYLOAD_TOO_LARGE: 413,
  URI_TOO_LONG: 414,
  UNSUPPORTED_MEDIA_TYPE: 415,
  RANGE_NOT_SATISFIABLE: 416,
  EXPECTATION_FAILED: 417,
  "I'M_A_TEAPOT": 418,
  MISDIRECTED_REQUEST: 421,
  UNPROCESSABLE_ENTITY: 422,
  LOCKED: 423,
  FAILED_DEPENDENCY: 424,
  TOO_EARLY: 425,
  UPGRADE_REQUIRED: 426,
  PRECONDITION_REQUIRED: 428,
  TOO_MANY_REQUESTS: 429,
  REQUEST_HEADER_FIELDS_TOO_LARGE: 431,
  UNAVAILABLE_FOR_LEGAL_REASONS: 451,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
  HTTP_VERSION_NOT_SUPPORTED: 505,
  VARIANT_ALSO_NEGOTIATES: 506,
  INSUFFICIENT_STORAGE: 507,
  LOOP_DETECTED: 508,
  NOT_EXTENDED: 510,
  NETWORK_AUTHENTICATION_REQUIRED: 511
};
var InternalAPIError = class extends Error {
  static {
    __name(this, "InternalAPIError");
  }
  constructor(status = "INTERNAL_SERVER_ERROR", body = void 0, headers = {}, statusCode = typeof status === "number" ? status : _statusCode[status]) {
    super(body?.message, body?.cause ? {
      cause: body.cause
    } : void 0);
    this.status = status;
    this.body = body;
    this.headers = headers;
    this.statusCode = statusCode;
    this.name = "APIError";
    this.status = status;
    this.headers = headers;
    this.statusCode = statusCode;
    this.body = body ? {
      code: body?.message?.toUpperCase().replace(/ /g, "_").replace(/[^A-Z0-9_]/g, ""),
      ...body
    } : void 0;
  }
};
var APIError = makeErrorForHideStackFrame(InternalAPIError, Error);
function isAPIError(error3) {
  return error3 instanceof APIError || error3?.name === "APIError";
}
__name(isAPIError, "isAPIError");
function tryDecode(str) {
  try {
    return str.includes("%") ? decodeURIComponent(str) : str;
  } catch {
    return str;
  }
}
__name(tryDecode, "tryDecode");
function isJSONSerializable(value) {
  if (value === void 0) {
    return false;
  }
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean" || t === null) {
    return true;
  }
  if (t !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return true;
  }
  if (value.buffer) {
    return false;
  }
  return value.constructor && value.constructor.name === "Object" || typeof value.toJSON === "function";
}
__name(isJSONSerializable, "isJSONSerializable");
function safeStringify(obj, replacer, space) {
  let id = 0;
  const seen = /* @__PURE__ */ new WeakMap();
  const safeReplacer = /* @__PURE__ */ __name((key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) {
        return `[Circular ref-${seen.get(value)}]`;
      }
      seen.set(value, id++);
    }
    if (replacer) {
      return replacer(key, value);
    }
    return value;
  }, "safeReplacer");
  return JSON.stringify(obj, safeReplacer, space);
}
__name(safeStringify, "safeStringify");
function isJSONResponse(value) {
  if (!value || typeof value !== "object") {
    return false;
  }
  return "_flag" in value && value._flag === "json";
}
__name(isJSONResponse, "isJSONResponse");
function toResponse(data, init) {
  if (data instanceof Response) {
    if (init?.headers instanceof Headers) {
      init.headers.forEach((value, key) => {
        data.headers.set(key, value);
      });
    }
    return data;
  }
  const isJSON = isJSONResponse(data);
  if (isJSON) {
    const body2 = data.body;
    const routerResponse = data.routerResponse;
    if (routerResponse instanceof Response) {
      return routerResponse;
    }
    const headers2 = new Headers({
      ...routerResponse?.headers,
      ...data.headers,
      ...init?.headers,
      "Content-Type": "application/json"
    });
    return new Response(JSON.stringify(body2), {
      ...routerResponse,
      headers: headers2,
      status: data.status ?? init?.status ?? routerResponse?.status,
      statusText: init?.statusText ?? routerResponse?.statusText
    });
  }
  if (isAPIError(data)) {
    return toResponse(data.body, {
      status: init?.status ?? data.statusCode,
      statusText: data.status.toString(),
      headers: init?.headers || data.headers
    });
  }
  let body = data;
  let headers = new Headers(init?.headers);
  if (!data) {
    if (data === null) {
      body = JSON.stringify(null);
    }
    headers.set("content-type", "application/json");
  } else if (typeof data === "string") {
    body = data;
    headers.set("Content-Type", "text/plain");
  } else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
    body = data;
    headers.set("Content-Type", "application/octet-stream");
  } else if (data instanceof Blob) {
    body = data;
    headers.set("Content-Type", data.type || "application/octet-stream");
  } else if (data instanceof FormData) {
    body = data;
  } else if (data instanceof URLSearchParams) {
    body = data;
    headers.set("Content-Type", "application/x-www-form-urlencoded");
  } else if (data instanceof ReadableStream) {
    body = data;
    headers.set("Content-Type", "application/octet-stream");
  } else if (isJSONSerializable(data)) {
    body = safeStringify(data);
    headers.set("Content-Type", "application/json");
  }
  return new Response(body, {
    ...init,
    headers
  });
}
__name(toResponse, "toResponse");
async function runValidation(options, context = {}) {
  let request = {
    body: context.body,
    query: context.query
  };
  if (options.body) {
    const result = await options.body["~standard"].validate(context.body);
    if (result.issues) {
      return {
        data: null,
        error: fromError(result.issues, "body")
      };
    }
    request.body = result.value;
  }
  if (options.query) {
    const result = await options.query["~standard"].validate(context.query);
    if (result.issues) {
      return {
        data: null,
        error: fromError(result.issues, "query")
      };
    }
    request.query = result.value;
  }
  if (options.requireHeaders && !context.headers) {
    return {
      data: null,
      error: {
        message: "Headers is required"
      }
    };
  }
  if (options.requireRequest && !context.request) {
    return {
      data: null,
      error: {
        message: "Request is required"
      }
    };
  }
  return {
    data: request,
    error: null
  };
}
__name(runValidation, "runValidation");
function fromError(error3, validating) {
  const errorMessages = [];
  for (const issue22 of error3) {
    const message2 = issue22.message;
    errorMessages.push(message2);
  }
  return {
    message: `Invalid ${validating} parameters`
  };
}
__name(fromError, "fromError");
var algorithm = {
  name: "HMAC",
  hash: "SHA-256"
};
var getCryptoKey = /* @__PURE__ */ __name(async (secret) => {
  const secretBuf = typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
  return await getWebcryptoSubtle().importKey("raw", secretBuf, algorithm, false, [
    "sign",
    "verify"
  ]);
}, "getCryptoKey");
var verifySignature = /* @__PURE__ */ __name(async (base64Signature, value, secret) => {
  try {
    const signatureBinStr = atob(base64Signature);
    const signature = new Uint8Array(signatureBinStr.length);
    for (let i = 0, len = signatureBinStr.length; i < len; i++) {
      signature[i] = signatureBinStr.charCodeAt(i);
    }
    return await getWebcryptoSubtle().verify(algorithm, secret, signature, new TextEncoder().encode(value));
  } catch (e) {
    return false;
  }
}, "verifySignature");
var makeSignature = /* @__PURE__ */ __name(async (value, secret) => {
  const key = await getCryptoKey(secret);
  const signature = await getWebcryptoSubtle().sign(algorithm.name, key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}, "makeSignature");
var signCookieValue = /* @__PURE__ */ __name(async (value, secret) => {
  const signature = await makeSignature(value, secret);
  value = `${value}.${signature}`;
  value = encodeURIComponent(value);
  return value;
}, "signCookieValue");
var getCookieKey = /* @__PURE__ */ __name((key, prefix) => {
  let finalKey = key;
  if (prefix) {
    if (prefix === "secure") {
      finalKey = "__Secure-" + key;
    } else if (prefix === "host") {
      finalKey = "__Host-" + key;
    } else {
      return void 0;
    }
  }
  return finalKey;
}, "getCookieKey");
function parseCookies(str) {
  if (typeof str !== "string") {
    throw new TypeError("argument str must be a string");
  }
  const cookies = /* @__PURE__ */ new Map();
  let index = 0;
  while (index < str.length) {
    const eqIdx = str.indexOf("=", index);
    if (eqIdx === -1) {
      break;
    }
    let endIdx = str.indexOf(";", index);
    if (endIdx === -1) {
      endIdx = str.length;
    } else if (endIdx < eqIdx) {
      index = str.lastIndexOf(";", eqIdx - 1) + 1;
      continue;
    }
    const key = str.slice(index, eqIdx).trim();
    if (!cookies.has(key)) {
      let val = str.slice(eqIdx + 1, endIdx).trim();
      if (val.codePointAt(0) === 34) {
        val = val.slice(1, -1);
      }
      cookies.set(key, tryDecode(val));
    }
    index = endIdx + 1;
  }
  return cookies;
}
__name(parseCookies, "parseCookies");
var _serialize = /* @__PURE__ */ __name((key, value, opt = {}) => {
  let cookie;
  if (opt?.prefix === "secure") {
    cookie = `${`__Secure-${key}`}=${value}`;
  } else if (opt?.prefix === "host") {
    cookie = `${`__Host-${key}`}=${value}`;
  } else {
    cookie = `${key}=${value}`;
  }
  if (key.startsWith("__Secure-") && !opt.secure) {
    opt.secure = true;
  }
  if (key.startsWith("__Host-")) {
    if (!opt.secure) {
      opt.secure = true;
    }
    if (opt.path !== "/") {
      opt.path = "/";
    }
    if (opt.domain) {
      opt.domain = void 0;
    }
  }
  if (opt && typeof opt.maxAge === "number" && opt.maxAge >= 0) {
    if (opt.maxAge > 3456e4) {
      throw new Error("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.");
    }
    cookie += `; Max-Age=${Math.floor(opt.maxAge)}`;
  }
  if (opt.domain && opt.prefix !== "host") {
    cookie += `; Domain=${opt.domain}`;
  }
  if (opt.path) {
    cookie += `; Path=${opt.path}`;
  }
  if (opt.expires) {
    if (opt.expires.getTime() - Date.now() > 3456e7) {
      throw new Error("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.");
    }
    cookie += `; Expires=${opt.expires.toUTCString()}`;
  }
  if (opt.httpOnly) {
    cookie += "; HttpOnly";
  }
  if (opt.secure) {
    cookie += "; Secure";
  }
  if (opt.sameSite) {
    cookie += `; SameSite=${opt.sameSite.charAt(0).toUpperCase() + opt.sameSite.slice(1)}`;
  }
  if (opt.partitioned) {
    if (!opt.secure) {
      opt.secure = true;
    }
    cookie += "; Partitioned";
  }
  return cookie;
}, "_serialize");
var serializeCookie = /* @__PURE__ */ __name((key, value, opt) => {
  value = encodeURIComponent(value);
  return _serialize(key, value, opt);
}, "serializeCookie");
var serializeSignedCookie = /* @__PURE__ */ __name(async (key, value, secret, opt) => {
  value = await signCookieValue(value, secret);
  return _serialize(key, value, opt);
}, "serializeSignedCookie");
var createInternalContext = /* @__PURE__ */ __name(async (context, { options, path }) => {
  const headers = new Headers();
  const { data, error: error3 } = await runValidation(options, context);
  if (error3) {
    throw new APIError(400, {
      message: error3.message,
      code: "VALIDATION_ERROR"
    });
  }
  const requestHeaders = "headers" in context ? context.headers instanceof Headers ? context.headers : new Headers(context.headers) : "request" in context && context.request instanceof Request ? context.request.headers : null;
  const requestCookies = requestHeaders?.get("cookie");
  const parsedCookies = requestCookies ? parseCookies(requestCookies) : void 0;
  const internalContext = {
    ...context,
    body: data.body,
    query: data.query,
    path: context.path || path,
    context: "context" in context && context.context ? context.context : {},
    returned: void 0,
    headers: context?.headers,
    request: context?.request,
    params: "params" in context ? context.params : void 0,
    method: context.method,
    setHeader: /* @__PURE__ */ __name((key, value) => {
      headers.set(key, value);
    }, "setHeader"),
    getHeader: /* @__PURE__ */ __name((key) => {
      if (!requestHeaders) return null;
      return requestHeaders.get(key);
    }, "getHeader"),
    getCookie: /* @__PURE__ */ __name((key, prefix) => {
      const finalKey = getCookieKey(key, prefix);
      if (!finalKey) {
        return null;
      }
      return parsedCookies?.get(finalKey) || null;
    }, "getCookie"),
    getSignedCookie: /* @__PURE__ */ __name(async (key, secret, prefix) => {
      const finalKey = getCookieKey(key, prefix);
      if (!finalKey) {
        return null;
      }
      const value = parsedCookies?.get(finalKey);
      if (!value) {
        return null;
      }
      const signatureStartPos = value.lastIndexOf(".");
      if (signatureStartPos < 1) {
        return null;
      }
      const signedValue = value.substring(0, signatureStartPos);
      const signature = value.substring(signatureStartPos + 1);
      if (signature.length !== 44 || !signature.endsWith("=")) {
        return null;
      }
      const secretKey = await getCryptoKey(secret);
      const isVerified = await verifySignature(signature, signedValue, secretKey);
      return isVerified ? signedValue : false;
    }, "getSignedCookie"),
    setCookie: /* @__PURE__ */ __name((key, value, options2) => {
      const cookie = serializeCookie(key, value, options2);
      headers.append("set-cookie", cookie);
      return cookie;
    }, "setCookie"),
    setSignedCookie: /* @__PURE__ */ __name(async (key, value, secret, options2) => {
      const cookie = await serializeSignedCookie(key, value, secret, options2);
      headers.append("set-cookie", cookie);
      return cookie;
    }, "setSignedCookie"),
    redirect: /* @__PURE__ */ __name((url) => {
      headers.set("location", url);
      return new APIError("FOUND", void 0, headers);
    }, "redirect"),
    error: /* @__PURE__ */ __name((status, body, headers2) => {
      return new APIError(status, body, headers2);
    }, "error"),
    json: /* @__PURE__ */ __name((json2, routerResponse) => {
      if (!context.asResponse) {
        return json2;
      }
      return {
        body: routerResponse?.body || json2,
        routerResponse,
        _flag: "json"
      };
    }, "json"),
    responseHeaders: headers
  };
  for (const middleware of options.use || []) {
    const response = await middleware({
      ...internalContext,
      returnHeaders: true,
      asResponse: false
    });
    if (response.response) {
      Object.assign(internalContext.context, response.response);
    }
    if (response.headers) {
      response.headers.forEach((value, key) => {
        internalContext.responseHeaders.set(key, value);
      });
    }
  }
  return internalContext;
}, "createInternalContext");
function createMiddleware(optionsOrHandler, handler) {
  const internalHandler = /* @__PURE__ */ __name(async (inputCtx) => {
    const context = inputCtx;
    const _handler = typeof optionsOrHandler === "function" ? optionsOrHandler : handler;
    const options = typeof optionsOrHandler === "function" ? {} : optionsOrHandler;
    const internalContext = await createInternalContext(context, {
      options,
      path: "/"
    });
    if (!_handler) {
      throw new Error("handler must be defined");
    }
    const response = await _handler(internalContext);
    const headers = internalContext.responseHeaders;
    return context.returnHeaders ? {
      headers,
      response
    } : response;
  }, "internalHandler");
  internalHandler.options = typeof optionsOrHandler === "function" ? {} : optionsOrHandler;
  return internalHandler;
}
__name(createMiddleware, "createMiddleware");
createMiddleware.create = (opts) => {
  function fn(optionsOrHandler, handler) {
    if (typeof optionsOrHandler === "function") {
      return createMiddleware({
        use: opts?.use
      }, optionsOrHandler);
    }
    if (!handler) {
      throw new Error("Middleware handler is required");
    }
    const middleware = createMiddleware({
      ...optionsOrHandler,
      method: "*",
      use: [
        ...opts?.use || [],
        ...optionsOrHandler.use || []
      ]
    }, handler);
    return middleware;
  }
  __name(fn, "fn");
  return fn;
};
var createEndpoint2 = /* @__PURE__ */ __name((path, options, handler) => {
  const internalHandler = /* @__PURE__ */ __name(async (...inputCtx) => {
    const context = inputCtx[0] || {};
    const internalContext = await createInternalContext(context, {
      options,
      path
    });
    const response = await handler(internalContext).catch(async (e) => {
      if (isAPIError(e)) {
        const onAPIError = options.onAPIError;
        if (onAPIError) {
          await onAPIError(e);
        }
        if (context.asResponse) {
          return e;
        }
      }
      throw e;
    });
    const headers = internalContext.responseHeaders;
    return context.asResponse ? toResponse(response, {
      headers
    }) : context.returnHeaders ? {
      headers,
      response
    } : response;
  }, "internalHandler");
  internalHandler.options = options;
  internalHandler.path = path;
  return internalHandler;
}, "createEndpoint2");
createEndpoint2.create = (opts) => {
  return (path, options, handler) => {
    return createEndpoint2(path, {
      ...options,
      use: [
        ...options?.use || [],
        ...opts?.use || []
      ]
    }, handler);
  };
};
var NEVER = Object.freeze({
  status: "aborted"
});
var util_exports = {};
__export2(util_exports, {
  BIGINT_FORMAT_RANGES: /* @__PURE__ */ __name(() => BIGINT_FORMAT_RANGES, "BIGINT_FORMAT_RANGES"),
  Class: /* @__PURE__ */ __name(() => Class, "Class"),
  NUMBER_FORMAT_RANGES: /* @__PURE__ */ __name(() => NUMBER_FORMAT_RANGES, "NUMBER_FORMAT_RANGES"),
  aborted: /* @__PURE__ */ __name(() => aborted, "aborted"),
  allowsEval: /* @__PURE__ */ __name(() => allowsEval, "allowsEval"),
  assert: /* @__PURE__ */ __name(() => assert, "assert"),
  assertEqual: /* @__PURE__ */ __name(() => assertEqual, "assertEqual"),
  assertIs: /* @__PURE__ */ __name(() => assertIs, "assertIs"),
  assertNever: /* @__PURE__ */ __name(() => assertNever, "assertNever"),
  assertNotEqual: /* @__PURE__ */ __name(() => assertNotEqual, "assertNotEqual"),
  assignProp: /* @__PURE__ */ __name(() => assignProp, "assignProp"),
  cached: /* @__PURE__ */ __name(() => cached, "cached"),
  captureStackTrace: /* @__PURE__ */ __name(() => captureStackTrace, "captureStackTrace"),
  cleanEnum: /* @__PURE__ */ __name(() => cleanEnum, "cleanEnum"),
  cleanRegex: /* @__PURE__ */ __name(() => cleanRegex, "cleanRegex"),
  clone: /* @__PURE__ */ __name(() => clone, "clone"),
  createTransparentProxy: /* @__PURE__ */ __name(() => createTransparentProxy, "createTransparentProxy"),
  defineLazy: /* @__PURE__ */ __name(() => defineLazy, "defineLazy"),
  esc: /* @__PURE__ */ __name(() => esc, "esc"),
  escapeRegex: /* @__PURE__ */ __name(() => escapeRegex, "escapeRegex"),
  extend: /* @__PURE__ */ __name(() => extend, "extend"),
  finalizeIssue: /* @__PURE__ */ __name(() => finalizeIssue, "finalizeIssue"),
  floatSafeRemainder: /* @__PURE__ */ __name(() => floatSafeRemainder, "floatSafeRemainder"),
  getElementAtPath: /* @__PURE__ */ __name(() => getElementAtPath, "getElementAtPath"),
  getEnumValues: /* @__PURE__ */ __name(() => getEnumValues, "getEnumValues"),
  getLengthableOrigin: /* @__PURE__ */ __name(() => getLengthableOrigin, "getLengthableOrigin"),
  getParsedType: /* @__PURE__ */ __name(() => getParsedType, "getParsedType"),
  getSizableOrigin: /* @__PURE__ */ __name(() => getSizableOrigin, "getSizableOrigin"),
  isObject: /* @__PURE__ */ __name(() => isObject, "isObject"),
  isPlainObject: /* @__PURE__ */ __name(() => isPlainObject, "isPlainObject"),
  issue: /* @__PURE__ */ __name(() => issue, "issue"),
  joinValues: /* @__PURE__ */ __name(() => joinValues, "joinValues"),
  jsonStringifyReplacer: /* @__PURE__ */ __name(() => jsonStringifyReplacer, "jsonStringifyReplacer"),
  merge: /* @__PURE__ */ __name(() => merge, "merge"),
  normalizeParams: /* @__PURE__ */ __name(() => normalizeParams, "normalizeParams"),
  nullish: /* @__PURE__ */ __name(() => nullish, "nullish"),
  numKeys: /* @__PURE__ */ __name(() => numKeys, "numKeys"),
  omit: /* @__PURE__ */ __name(() => omit, "omit"),
  optionalKeys: /* @__PURE__ */ __name(() => optionalKeys, "optionalKeys"),
  partial: /* @__PURE__ */ __name(() => partial, "partial"),
  pick: /* @__PURE__ */ __name(() => pick, "pick"),
  prefixIssues: /* @__PURE__ */ __name(() => prefixIssues, "prefixIssues"),
  primitiveTypes: /* @__PURE__ */ __name(() => primitiveTypes, "primitiveTypes"),
  promiseAllObject: /* @__PURE__ */ __name(() => promiseAllObject, "promiseAllObject"),
  propertyKeyTypes: /* @__PURE__ */ __name(() => propertyKeyTypes, "propertyKeyTypes"),
  randomString: /* @__PURE__ */ __name(() => randomString, "randomString"),
  required: /* @__PURE__ */ __name(() => required, "required"),
  stringifyPrimitive: /* @__PURE__ */ __name(() => stringifyPrimitive, "stringifyPrimitive"),
  unwrapMessage: /* @__PURE__ */ __name(() => unwrapMessage, "unwrapMessage")
});
function assertEqual(val) {
  return val;
}
__name(assertEqual, "assertEqual");
function assertNotEqual(val) {
  return val;
}
__name(assertNotEqual, "assertNotEqual");
function assertIs(_arg) {
}
__name(assertIs, "assertIs");
function assertNever(_x) {
  throw new Error();
}
__name(assertNever, "assertNever");
function assert(_) {
}
__name(assert, "assert");
function getEnumValues(entries) {
  const numericValues = Object.values(entries).filter((v) => typeof v === "number");
  const values = Object.entries(entries).filter(([k, _]) => numericValues.indexOf(+k) === -1).map(([_, v]) => v);
  return values;
}
__name(getEnumValues, "getEnumValues");
function joinValues(array2, separator = "|") {
  return array2.map((val) => stringifyPrimitive(val)).join(separator);
}
__name(joinValues, "joinValues");
function jsonStringifyReplacer(_, value) {
  if (typeof value === "bigint") return value.toString();
  return value;
}
__name(jsonStringifyReplacer, "jsonStringifyReplacer");
function cached(getter) {
  const set = false;
  return {
    get value() {
      if (!set) {
        const value = getter();
        Object.defineProperty(this, "value", {
          value
        });
        return value;
      }
      throw new Error("cached value already set");
    }
  };
}
__name(cached, "cached");
function nullish(input) {
  return input === null || input === void 0;
}
__name(nullish, "nullish");
function cleanRegex(source) {
  const start = source.startsWith("^") ? 1 : 0;
  const end = source.endsWith("$") ? source.length - 1 : source.length;
  return source.slice(start, end);
}
__name(cleanRegex, "cleanRegex");
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
__name(floatSafeRemainder, "floatSafeRemainder");
function defineLazy(object2, key, getter) {
  const set = false;
  Object.defineProperty(object2, key, {
    get() {
      if (!set) {
        const value = getter();
        object2[key] = value;
        return value;
      }
      throw new Error("cached value already set");
    },
    set(v) {
      Object.defineProperty(object2, key, {
        value: v
      });
    },
    configurable: true
  });
}
__name(defineLazy, "defineLazy");
function assignProp(target, prop, value) {
  Object.defineProperty(target, prop, {
    value,
    writable: true,
    enumerable: true,
    configurable: true
  });
}
__name(assignProp, "assignProp");
function getElementAtPath(obj, path) {
  if (!path) return obj;
  return path.reduce((acc, key) => acc?.[key], obj);
}
__name(getElementAtPath, "getElementAtPath");
function promiseAllObject(promisesObj) {
  const keys = Object.keys(promisesObj);
  const promises = keys.map((key) => promisesObj[key]);
  return Promise.all(promises).then((results) => {
    const resolvedObj = {};
    for (let i = 0; i < keys.length; i++) {
      resolvedObj[keys[i]] = results[i];
    }
    return resolvedObj;
  });
}
__name(promiseAllObject, "promiseAllObject");
function randomString(length = 10) {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  let str = "";
  for (let i = 0; i < length; i++) {
    str += chars[Math.floor(Math.random() * chars.length)];
  }
  return str;
}
__name(randomString, "randomString");
function esc(str) {
  return JSON.stringify(str);
}
__name(esc, "esc");
var captureStackTrace = Error.captureStackTrace ? Error.captureStackTrace : (..._args) => {
};
function isObject(data) {
  return typeof data === "object" && data !== null && !Array.isArray(data);
}
__name(isObject, "isObject");
var allowsEval = cached(() => {
  if (typeof navigator !== "undefined" && navigator?.userAgent?.includes("Cloudflare")) {
    return false;
  }
  try {
    const F = Function;
    new F("");
    return true;
  } catch (_) {
    return false;
  }
});
function isPlainObject(o) {
  if (isObject(o) === false) return false;
  const ctor = o.constructor;
  if (ctor === void 0) return true;
  const prot = ctor.prototype;
  if (isObject(prot) === false) return false;
  if (Object.prototype.hasOwnProperty.call(prot, "isPrototypeOf") === false) {
    return false;
  }
  return true;
}
__name(isPlainObject, "isPlainObject");
function numKeys(data) {
  let keyCount = 0;
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      keyCount++;
    }
  }
  return keyCount;
}
__name(numKeys, "numKeys");
var getParsedType = /* @__PURE__ */ __name((data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return "undefined";
    case "string":
      return "string";
    case "number":
      return Number.isNaN(data) ? "nan" : "number";
    case "boolean":
      return "boolean";
    case "function":
      return "function";
    case "bigint":
      return "bigint";
    case "symbol":
      return "symbol";
    case "object":
      if (Array.isArray(data)) {
        return "array";
      }
      if (data === null) {
        return "null";
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return "promise";
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return "map";
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return "set";
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return "date";
      }
      if (typeof File !== "undefined" && data instanceof File) {
        return "file";
      }
      return "object";
    default:
      throw new Error(`Unknown data type: ${t}`);
  }
}, "getParsedType");
var propertyKeyTypes = /* @__PURE__ */ new Set([
  "string",
  "number",
  "symbol"
]);
var primitiveTypes = /* @__PURE__ */ new Set([
  "string",
  "number",
  "bigint",
  "boolean",
  "symbol",
  "undefined"
]);
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
__name(escapeRegex, "escapeRegex");
function clone(inst, def, params) {
  const cl = new inst._zod.constr(def ?? inst._zod.def);
  if (!def || params?.parent) cl._zod.parent = inst;
  return cl;
}
__name(clone, "clone");
function normalizeParams(_params) {
  const params = _params;
  if (!params) return {};
  if (typeof params === "string") return {
    error: /* @__PURE__ */ __name(() => params, "error")
  };
  if (params?.message !== void 0) {
    if (params?.error !== void 0) throw new Error("Cannot specify both `message` and `error` params");
    params.error = params.message;
  }
  delete params.message;
  if (typeof params.error === "string") return {
    ...params,
    error: /* @__PURE__ */ __name(() => params.error, "error")
  };
  return params;
}
__name(normalizeParams, "normalizeParams");
function createTransparentProxy(getter) {
  let target;
  return new Proxy({}, {
    get(_, prop, receiver) {
      target ?? (target = getter());
      return Reflect.get(target, prop, receiver);
    },
    set(_, prop, value, receiver) {
      target ?? (target = getter());
      return Reflect.set(target, prop, value, receiver);
    },
    has(_, prop) {
      target ?? (target = getter());
      return Reflect.has(target, prop);
    },
    deleteProperty(_, prop) {
      target ?? (target = getter());
      return Reflect.deleteProperty(target, prop);
    },
    ownKeys(_) {
      target ?? (target = getter());
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(_, prop) {
      target ?? (target = getter());
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
    defineProperty(_, prop, descriptor) {
      target ?? (target = getter());
      return Reflect.defineProperty(target, prop, descriptor);
    }
  });
}
__name(createTransparentProxy, "createTransparentProxy");
function stringifyPrimitive(value) {
  if (typeof value === "bigint") return value.toString() + "n";
  if (typeof value === "string") return `"${value}"`;
  return `${value}`;
}
__name(stringifyPrimitive, "stringifyPrimitive");
function optionalKeys(shape) {
  return Object.keys(shape).filter((k) => {
    return shape[k]._zod.optin === "optional" && shape[k]._zod.optout === "optional";
  });
}
__name(optionalKeys, "optionalKeys");
var NUMBER_FORMAT_RANGES = {
  safeint: [
    Number.MIN_SAFE_INTEGER,
    Number.MAX_SAFE_INTEGER
  ],
  int32: [
    -2147483648,
    2147483647
  ],
  uint32: [
    0,
    4294967295
  ],
  float32: [
    -34028234663852886e22,
    34028234663852886e22
  ],
  float64: [
    -Number.MAX_VALUE,
    Number.MAX_VALUE
  ]
};
var BIGINT_FORMAT_RANGES = {
  int64: [
    /* @__PURE__ */ BigInt("-9223372036854775808"),
    /* @__PURE__ */ BigInt("9223372036854775807")
  ],
  uint64: [
    /* @__PURE__ */ BigInt(0),
    /* @__PURE__ */ BigInt("18446744073709551615")
  ]
};
function pick(schema3, mask) {
  const newShape = {};
  const currDef = schema3._zod.def;
  for (const key in mask) {
    if (!(key in currDef.shape)) {
      throw new Error(`Unrecognized key: "${key}"`);
    }
    if (!mask[key]) continue;
    newShape[key] = currDef.shape[key];
  }
  return clone(schema3, {
    ...schema3._zod.def,
    shape: newShape,
    checks: []
  });
}
__name(pick, "pick");
function omit(schema3, mask) {
  const newShape = {
    ...schema3._zod.def.shape
  };
  const currDef = schema3._zod.def;
  for (const key in mask) {
    if (!(key in currDef.shape)) {
      throw new Error(`Unrecognized key: "${key}"`);
    }
    if (!mask[key]) continue;
    delete newShape[key];
  }
  return clone(schema3, {
    ...schema3._zod.def,
    shape: newShape,
    checks: []
  });
}
__name(omit, "omit");
function extend(schema3, shape) {
  if (!isPlainObject(shape)) {
    throw new Error("Invalid input to extend: expected a plain object");
  }
  const def = {
    ...schema3._zod.def,
    get shape() {
      const _shape = {
        ...schema3._zod.def.shape,
        ...shape
      };
      assignProp(this, "shape", _shape);
      return _shape;
    },
    checks: []
  };
  return clone(schema3, def);
}
__name(extend, "extend");
function merge(a, b) {
  return clone(a, {
    ...a._zod.def,
    get shape() {
      const _shape = {
        ...a._zod.def.shape,
        ...b._zod.def.shape
      };
      assignProp(this, "shape", _shape);
      return _shape;
    },
    catchall: b._zod.def.catchall,
    checks: []
  });
}
__name(merge, "merge");
function partial(Class22, schema3, mask) {
  const oldShape = schema3._zod.def.shape;
  const shape = {
    ...oldShape
  };
  if (mask) {
    for (const key in mask) {
      if (!(key in oldShape)) {
        throw new Error(`Unrecognized key: "${key}"`);
      }
      if (!mask[key]) continue;
      shape[key] = Class22 ? new Class22({
        type: "optional",
        innerType: oldShape[key]
      }) : oldShape[key];
    }
  } else {
    for (const key in oldShape) {
      shape[key] = Class22 ? new Class22({
        type: "optional",
        innerType: oldShape[key]
      }) : oldShape[key];
    }
  }
  return clone(schema3, {
    ...schema3._zod.def,
    shape,
    checks: []
  });
}
__name(partial, "partial");
function required(Class22, schema3, mask) {
  const oldShape = schema3._zod.def.shape;
  const shape = {
    ...oldShape
  };
  if (mask) {
    for (const key in mask) {
      if (!(key in shape)) {
        throw new Error(`Unrecognized key: "${key}"`);
      }
      if (!mask[key]) continue;
      shape[key] = new Class22({
        type: "nonoptional",
        innerType: oldShape[key]
      });
    }
  } else {
    for (const key in oldShape) {
      shape[key] = new Class22({
        type: "nonoptional",
        innerType: oldShape[key]
      });
    }
  }
  return clone(schema3, {
    ...schema3._zod.def,
    shape,
    // optional: [],
    checks: []
  });
}
__name(required, "required");
function aborted(x, startIndex = 0) {
  for (let i = startIndex; i < x.issues.length; i++) {
    if (x.issues[i]?.continue !== true) return true;
  }
  return false;
}
__name(aborted, "aborted");
function prefixIssues(path, issues) {
  return issues.map((iss) => {
    var _a;
    (_a = iss).path ?? (_a.path = []);
    iss.path.unshift(path);
    return iss;
  });
}
__name(prefixIssues, "prefixIssues");
function unwrapMessage(message2) {
  return typeof message2 === "string" ? message2 : message2?.message;
}
__name(unwrapMessage, "unwrapMessage");
function finalizeIssue(iss, ctx, config2) {
  const full = {
    ...iss,
    path: iss.path ?? []
  };
  if (!iss.message) {
    const message2 = unwrapMessage(iss.inst?._zod.def?.error?.(iss)) ?? unwrapMessage(ctx?.error?.(iss)) ?? unwrapMessage(config2.customError?.(iss)) ?? unwrapMessage(config2.localeError?.(iss)) ?? "Invalid input";
    full.message = message2;
  }
  delete full.inst;
  delete full.continue;
  if (!ctx?.reportInput) {
    delete full.input;
  }
  return full;
}
__name(finalizeIssue, "finalizeIssue");
function getSizableOrigin(input) {
  if (input instanceof Set) return "set";
  if (input instanceof Map) return "map";
  if (input instanceof File) return "file";
  return "unknown";
}
__name(getSizableOrigin, "getSizableOrigin");
function getLengthableOrigin(input) {
  if (Array.isArray(input)) return "array";
  if (typeof input === "string") return "string";
  return "unknown";
}
__name(getLengthableOrigin, "getLengthableOrigin");
function issue(...args) {
  const [iss, input, inst] = args;
  if (typeof iss === "string") {
    return {
      message: iss,
      code: "custom",
      input,
      inst
    };
  }
  return {
    ...iss
  };
}
__name(issue, "issue");
function cleanEnum(obj) {
  return Object.entries(obj).filter(([k, _]) => {
    return Number.isNaN(Number.parseInt(k, 10));
  }).map((el) => el[1]);
}
__name(cleanEnum, "cleanEnum");
var Class = class {
  static {
    __name(this, "Class");
  }
  constructor(..._args) {
  }
};

// node_modules/zod/v4/core/core.js
var NEVER2 = Object.freeze({
  status: "aborted"
});
// @__NO_SIDE_EFFECTS__
function $constructor(name, initializer3, params) {
  function init(inst, def) {
    var _a;
    Object.defineProperty(inst, "_zod", {
      value: inst._zod ?? {},
      enumerable: false
    });
    (_a = inst._zod).traits ?? (_a.traits = /* @__PURE__ */ new Set());
    inst._zod.traits.add(name);
    initializer3(inst, def);
    for (const k in _.prototype) {
      if (!(k in inst)) Object.defineProperty(inst, k, {
        value: _.prototype[k].bind(inst)
      });
    }
    inst._zod.constr = _;
    inst._zod.def = def;
  }
  __name(init, "init");
  const Parent = params?.Parent ?? Object;
  let Definition = class Definition extends Parent {
    static {
      __name(this, "Definition");
    }
  };
  Object.defineProperty(Definition, "name", {
    value: name
  });
  function _(def) {
    var _a;
    const inst = params?.Parent ? new Definition() : this;
    init(inst, def);
    (_a = inst._zod).deferred ?? (_a.deferred = []);
    for (const fn of inst._zod.deferred) {
      fn();
    }
    return inst;
  }
  __name(_, "_");
  Object.defineProperty(_, "init", {
    value: init
  });
  Object.defineProperty(_, Symbol.hasInstance, {
    value: /* @__PURE__ */ __name((inst) => {
      if (params?.Parent && inst instanceof params.Parent) return true;
      return inst?._zod?.traits?.has(name);
    }, "value")
  });
  Object.defineProperty(_, "name", {
    value: name
  });
  return _;
}
__name($constructor, "$constructor");
var $ZodAsyncError = class extends Error {
  static {
    __name(this, "$ZodAsyncError");
  }
  constructor() {
    super(`Encountered Promise during synchronous parse. Use .parseAsync() instead.`);
  }
};
var $ZodEncodeError = class extends Error {
  static {
    __name(this, "$ZodEncodeError");
  }
  constructor(name) {
    super(`Encountered unidirectional transform during encode: ${name}`);
    this.name = "ZodEncodeError";
  }
};
var globalConfig = {};
function config(newConfig) {
  if (newConfig) Object.assign(globalConfig, newConfig);
  return globalConfig;
}
__name(config, "config");

// node_modules/zod/v4/core/util.js
var util_exports2 = {};
__export(util_exports2, {
  BIGINT_FORMAT_RANGES: () => BIGINT_FORMAT_RANGES2,
  Class: () => Class2,
  NUMBER_FORMAT_RANGES: () => NUMBER_FORMAT_RANGES2,
  aborted: () => aborted2,
  allowsEval: () => allowsEval2,
  assert: () => assert2,
  assertEqual: () => assertEqual2,
  assertIs: () => assertIs2,
  assertNever: () => assertNever2,
  assertNotEqual: () => assertNotEqual2,
  assignProp: () => assignProp2,
  base64ToUint8Array: () => base64ToUint8Array,
  base64urlToUint8Array: () => base64urlToUint8Array,
  cached: () => cached2,
  captureStackTrace: () => captureStackTrace2,
  cleanEnum: () => cleanEnum2,
  cleanRegex: () => cleanRegex2,
  clone: () => clone2,
  cloneDef: () => cloneDef,
  createTransparentProxy: () => createTransparentProxy2,
  defineLazy: () => defineLazy2,
  esc: () => esc2,
  escapeRegex: () => escapeRegex2,
  extend: () => extend2,
  finalizeIssue: () => finalizeIssue2,
  floatSafeRemainder: () => floatSafeRemainder2,
  getElementAtPath: () => getElementAtPath2,
  getEnumValues: () => getEnumValues2,
  getLengthableOrigin: () => getLengthableOrigin2,
  getParsedType: () => getParsedType2,
  getSizableOrigin: () => getSizableOrigin2,
  hexToUint8Array: () => hexToUint8Array,
  isObject: () => isObject2,
  isPlainObject: () => isPlainObject2,
  issue: () => issue2,
  joinValues: () => joinValues2,
  jsonStringifyReplacer: () => jsonStringifyReplacer2,
  merge: () => merge2,
  mergeDefs: () => mergeDefs,
  normalizeParams: () => normalizeParams2,
  nullish: () => nullish2,
  numKeys: () => numKeys2,
  objectClone: () => objectClone,
  omit: () => omit2,
  optionalKeys: () => optionalKeys2,
  partial: () => partial2,
  pick: () => pick2,
  prefixIssues: () => prefixIssues2,
  primitiveTypes: () => primitiveTypes2,
  promiseAllObject: () => promiseAllObject2,
  propertyKeyTypes: () => propertyKeyTypes2,
  randomString: () => randomString2,
  required: () => required2,
  safeExtend: () => safeExtend,
  shallowClone: () => shallowClone,
  stringifyPrimitive: () => stringifyPrimitive2,
  uint8ArrayToBase64: () => uint8ArrayToBase64,
  uint8ArrayToBase64url: () => uint8ArrayToBase64url,
  uint8ArrayToHex: () => uint8ArrayToHex,
  unwrapMessage: () => unwrapMessage2
});
function assertEqual2(val) {
  return val;
}
__name(assertEqual2, "assertEqual");
function assertNotEqual2(val) {
  return val;
}
__name(assertNotEqual2, "assertNotEqual");
function assertIs2(_arg) {
}
__name(assertIs2, "assertIs");
function assertNever2(_x) {
  throw new Error();
}
__name(assertNever2, "assertNever");
function assert2(_) {
}
__name(assert2, "assert");
function getEnumValues2(entries) {
  const numericValues = Object.values(entries).filter((v) => typeof v === "number");
  const values = Object.entries(entries).filter(([k, _]) => numericValues.indexOf(+k) === -1).map(([_, v]) => v);
  return values;
}
__name(getEnumValues2, "getEnumValues");
function joinValues2(array2, separator = "|") {
  return array2.map((val) => stringifyPrimitive2(val)).join(separator);
}
__name(joinValues2, "joinValues");
function jsonStringifyReplacer2(_, value) {
  if (typeof value === "bigint") return value.toString();
  return value;
}
__name(jsonStringifyReplacer2, "jsonStringifyReplacer");
function cached2(getter) {
  const set = false;
  return {
    get value() {
      if (!set) {
        const value = getter();
        Object.defineProperty(this, "value", {
          value
        });
        return value;
      }
      throw new Error("cached value already set");
    }
  };
}
__name(cached2, "cached");
function nullish2(input) {
  return input === null || input === void 0;
}
__name(nullish2, "nullish");
function cleanRegex2(source) {
  const start = source.startsWith("^") ? 1 : 0;
  const end = source.endsWith("$") ? source.length - 1 : source.length;
  return source.slice(start, end);
}
__name(cleanRegex2, "cleanRegex");
function floatSafeRemainder2(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepString = step.toString();
  let stepDecCount = (stepString.split(".")[1] || "").length;
  if (stepDecCount === 0 && /\d?e-\d?/.test(stepString)) {
    const match = stepString.match(/\d?e-(\d?)/);
    if (match?.[1]) {
      stepDecCount = Number.parseInt(match[1]);
    }
  }
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
__name(floatSafeRemainder2, "floatSafeRemainder");
var EVALUATING = /* @__PURE__ */ Symbol("evaluating");
function defineLazy2(object2, key, getter) {
  let value = void 0;
  Object.defineProperty(object2, key, {
    get() {
      if (value === EVALUATING) {
        return void 0;
      }
      if (value === void 0) {
        value = EVALUATING;
        value = getter();
      }
      return value;
    },
    set(v) {
      Object.defineProperty(object2, key, {
        value: v
      });
    },
    configurable: true
  });
}
__name(defineLazy2, "defineLazy");
function objectClone(obj) {
  return Object.create(Object.getPrototypeOf(obj), Object.getOwnPropertyDescriptors(obj));
}
__name(objectClone, "objectClone");
function assignProp2(target, prop, value) {
  Object.defineProperty(target, prop, {
    value,
    writable: true,
    enumerable: true,
    configurable: true
  });
}
__name(assignProp2, "assignProp");
function mergeDefs(...defs) {
  const mergedDescriptors = {};
  for (const def of defs) {
    const descriptors = Object.getOwnPropertyDescriptors(def);
    Object.assign(mergedDescriptors, descriptors);
  }
  return Object.defineProperties({}, mergedDescriptors);
}
__name(mergeDefs, "mergeDefs");
function cloneDef(schema3) {
  return mergeDefs(schema3._zod.def);
}
__name(cloneDef, "cloneDef");
function getElementAtPath2(obj, path) {
  if (!path) return obj;
  return path.reduce((acc, key) => acc?.[key], obj);
}
__name(getElementAtPath2, "getElementAtPath");
function promiseAllObject2(promisesObj) {
  const keys = Object.keys(promisesObj);
  const promises = keys.map((key) => promisesObj[key]);
  return Promise.all(promises).then((results) => {
    const resolvedObj = {};
    for (let i = 0; i < keys.length; i++) {
      resolvedObj[keys[i]] = results[i];
    }
    return resolvedObj;
  });
}
__name(promiseAllObject2, "promiseAllObject");
function randomString2(length = 10) {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  let str = "";
  for (let i = 0; i < length; i++) {
    str += chars[Math.floor(Math.random() * chars.length)];
  }
  return str;
}
__name(randomString2, "randomString");
function esc2(str) {
  return JSON.stringify(str);
}
__name(esc2, "esc");
var captureStackTrace2 = "captureStackTrace" in Error ? Error.captureStackTrace : (..._args) => {
};
function isObject2(data) {
  return typeof data === "object" && data !== null && !Array.isArray(data);
}
__name(isObject2, "isObject");
var allowsEval2 = cached2(() => {
  if (typeof navigator !== "undefined" && navigator?.userAgent?.includes("Cloudflare")) {
    return false;
  }
  try {
    const F = Function;
    new F("");
    return true;
  } catch (_) {
    return false;
  }
});
function isPlainObject2(o) {
  if (isObject2(o) === false) return false;
  const ctor = o.constructor;
  if (ctor === void 0) return true;
  const prot = ctor.prototype;
  if (isObject2(prot) === false) return false;
  if (Object.prototype.hasOwnProperty.call(prot, "isPrototypeOf") === false) {
    return false;
  }
  return true;
}
__name(isPlainObject2, "isPlainObject");
function shallowClone(o) {
  if (isPlainObject2(o)) return {
    ...o
  };
  if (Array.isArray(o)) return [
    ...o
  ];
  return o;
}
__name(shallowClone, "shallowClone");
function numKeys2(data) {
  let keyCount = 0;
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      keyCount++;
    }
  }
  return keyCount;
}
__name(numKeys2, "numKeys");
var getParsedType2 = /* @__PURE__ */ __name((data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return "undefined";
    case "string":
      return "string";
    case "number":
      return Number.isNaN(data) ? "nan" : "number";
    case "boolean":
      return "boolean";
    case "function":
      return "function";
    case "bigint":
      return "bigint";
    case "symbol":
      return "symbol";
    case "object":
      if (Array.isArray(data)) {
        return "array";
      }
      if (data === null) {
        return "null";
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return "promise";
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return "map";
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return "set";
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return "date";
      }
      if (typeof File !== "undefined" && data instanceof File) {
        return "file";
      }
      return "object";
    default:
      throw new Error(`Unknown data type: ${t}`);
  }
}, "getParsedType");
var propertyKeyTypes2 = /* @__PURE__ */ new Set([
  "string",
  "number",
  "symbol"
]);
var primitiveTypes2 = /* @__PURE__ */ new Set([
  "string",
  "number",
  "bigint",
  "boolean",
  "symbol",
  "undefined"
]);
function escapeRegex2(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
__name(escapeRegex2, "escapeRegex");
function clone2(inst, def, params) {
  const cl = new inst._zod.constr(def ?? inst._zod.def);
  if (!def || params?.parent) cl._zod.parent = inst;
  return cl;
}
__name(clone2, "clone");
function normalizeParams2(_params) {
  const params = _params;
  if (!params) return {};
  if (typeof params === "string") return {
    error: /* @__PURE__ */ __name(() => params, "error")
  };
  if (params?.message !== void 0) {
    if (params?.error !== void 0) throw new Error("Cannot specify both `message` and `error` params");
    params.error = params.message;
  }
  delete params.message;
  if (typeof params.error === "string") return {
    ...params,
    error: /* @__PURE__ */ __name(() => params.error, "error")
  };
  return params;
}
__name(normalizeParams2, "normalizeParams");
function createTransparentProxy2(getter) {
  let target;
  return new Proxy({}, {
    get(_, prop, receiver) {
      target ?? (target = getter());
      return Reflect.get(target, prop, receiver);
    },
    set(_, prop, value, receiver) {
      target ?? (target = getter());
      return Reflect.set(target, prop, value, receiver);
    },
    has(_, prop) {
      target ?? (target = getter());
      return Reflect.has(target, prop);
    },
    deleteProperty(_, prop) {
      target ?? (target = getter());
      return Reflect.deleteProperty(target, prop);
    },
    ownKeys(_) {
      target ?? (target = getter());
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(_, prop) {
      target ?? (target = getter());
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
    defineProperty(_, prop, descriptor) {
      target ?? (target = getter());
      return Reflect.defineProperty(target, prop, descriptor);
    }
  });
}
__name(createTransparentProxy2, "createTransparentProxy");
function stringifyPrimitive2(value) {
  if (typeof value === "bigint") return value.toString() + "n";
  if (typeof value === "string") return `"${value}"`;
  return `${value}`;
}
__name(stringifyPrimitive2, "stringifyPrimitive");
function optionalKeys2(shape) {
  return Object.keys(shape).filter((k) => {
    return shape[k]._zod.optin === "optional" && shape[k]._zod.optout === "optional";
  });
}
__name(optionalKeys2, "optionalKeys");
var NUMBER_FORMAT_RANGES2 = {
  safeint: [
    Number.MIN_SAFE_INTEGER,
    Number.MAX_SAFE_INTEGER
  ],
  int32: [
    -2147483648,
    2147483647
  ],
  uint32: [
    0,
    4294967295
  ],
  float32: [
    -34028234663852886e22,
    34028234663852886e22
  ],
  float64: [
    -Number.MAX_VALUE,
    Number.MAX_VALUE
  ]
};
var BIGINT_FORMAT_RANGES2 = {
  int64: [
    /* @__PURE__ */ BigInt("-9223372036854775808"),
    /* @__PURE__ */ BigInt("9223372036854775807")
  ],
  uint64: [
    /* @__PURE__ */ BigInt(0),
    /* @__PURE__ */ BigInt("18446744073709551615")
  ]
};
function pick2(schema3, mask) {
  const currDef = schema3._zod.def;
  const def = mergeDefs(schema3._zod.def, {
    get shape() {
      const newShape = {};
      for (const key in mask) {
        if (!(key in currDef.shape)) {
          throw new Error(`Unrecognized key: "${key}"`);
        }
        if (!mask[key]) continue;
        newShape[key] = currDef.shape[key];
      }
      assignProp2(this, "shape", newShape);
      return newShape;
    },
    checks: []
  });
  return clone2(schema3, def);
}
__name(pick2, "pick");
function omit2(schema3, mask) {
  const currDef = schema3._zod.def;
  const def = mergeDefs(schema3._zod.def, {
    get shape() {
      const newShape = {
        ...schema3._zod.def.shape
      };
      for (const key in mask) {
        if (!(key in currDef.shape)) {
          throw new Error(`Unrecognized key: "${key}"`);
        }
        if (!mask[key]) continue;
        delete newShape[key];
      }
      assignProp2(this, "shape", newShape);
      return newShape;
    },
    checks: []
  });
  return clone2(schema3, def);
}
__name(omit2, "omit");
function extend2(schema3, shape) {
  if (!isPlainObject2(shape)) {
    throw new Error("Invalid input to extend: expected a plain object");
  }
  const checks = schema3._zod.def.checks;
  const hasChecks = checks && checks.length > 0;
  if (hasChecks) {
    throw new Error("Object schemas containing refinements cannot be extended. Use `.safeExtend()` instead.");
  }
  const def = mergeDefs(schema3._zod.def, {
    get shape() {
      const _shape = {
        ...schema3._zod.def.shape,
        ...shape
      };
      assignProp2(this, "shape", _shape);
      return _shape;
    },
    checks: []
  });
  return clone2(schema3, def);
}
__name(extend2, "extend");
function safeExtend(schema3, shape) {
  if (!isPlainObject2(shape)) {
    throw new Error("Invalid input to safeExtend: expected a plain object");
  }
  const def = {
    ...schema3._zod.def,
    get shape() {
      const _shape = {
        ...schema3._zod.def.shape,
        ...shape
      };
      assignProp2(this, "shape", _shape);
      return _shape;
    },
    checks: schema3._zod.def.checks
  };
  return clone2(schema3, def);
}
__name(safeExtend, "safeExtend");
function merge2(a, b) {
  const def = mergeDefs(a._zod.def, {
    get shape() {
      const _shape = {
        ...a._zod.def.shape,
        ...b._zod.def.shape
      };
      assignProp2(this, "shape", _shape);
      return _shape;
    },
    get catchall() {
      return b._zod.def.catchall;
    },
    checks: []
  });
  return clone2(a, def);
}
__name(merge2, "merge");
function partial2(Class3, schema3, mask) {
  const def = mergeDefs(schema3._zod.def, {
    get shape() {
      const oldShape = schema3._zod.def.shape;
      const shape = {
        ...oldShape
      };
      if (mask) {
        for (const key in mask) {
          if (!(key in oldShape)) {
            throw new Error(`Unrecognized key: "${key}"`);
          }
          if (!mask[key]) continue;
          shape[key] = Class3 ? new Class3({
            type: "optional",
            innerType: oldShape[key]
          }) : oldShape[key];
        }
      } else {
        for (const key in oldShape) {
          shape[key] = Class3 ? new Class3({
            type: "optional",
            innerType: oldShape[key]
          }) : oldShape[key];
        }
      }
      assignProp2(this, "shape", shape);
      return shape;
    },
    checks: []
  });
  return clone2(schema3, def);
}
__name(partial2, "partial");
function required2(Class3, schema3, mask) {
  const def = mergeDefs(schema3._zod.def, {
    get shape() {
      const oldShape = schema3._zod.def.shape;
      const shape = {
        ...oldShape
      };
      if (mask) {
        for (const key in mask) {
          if (!(key in shape)) {
            throw new Error(`Unrecognized key: "${key}"`);
          }
          if (!mask[key]) continue;
          shape[key] = new Class3({
            type: "nonoptional",
            innerType: oldShape[key]
          });
        }
      } else {
        for (const key in oldShape) {
          shape[key] = new Class3({
            type: "nonoptional",
            innerType: oldShape[key]
          });
        }
      }
      assignProp2(this, "shape", shape);
      return shape;
    },
    checks: []
  });
  return clone2(schema3, def);
}
__name(required2, "required");
function aborted2(x, startIndex = 0) {
  if (x.aborted === true) return true;
  for (let i = startIndex; i < x.issues.length; i++) {
    if (x.issues[i]?.continue !== true) {
      return true;
    }
  }
  return false;
}
__name(aborted2, "aborted");
function prefixIssues2(path, issues) {
  return issues.map((iss) => {
    var _a;
    (_a = iss).path ?? (_a.path = []);
    iss.path.unshift(path);
    return iss;
  });
}
__name(prefixIssues2, "prefixIssues");
function unwrapMessage2(message2) {
  return typeof message2 === "string" ? message2 : message2?.message;
}
__name(unwrapMessage2, "unwrapMessage");
function finalizeIssue2(iss, ctx, config2) {
  const full = {
    ...iss,
    path: iss.path ?? []
  };
  if (!iss.message) {
    const message2 = unwrapMessage2(iss.inst?._zod.def?.error?.(iss)) ?? unwrapMessage2(ctx?.error?.(iss)) ?? unwrapMessage2(config2.customError?.(iss)) ?? unwrapMessage2(config2.localeError?.(iss)) ?? "Invalid input";
    full.message = message2;
  }
  delete full.inst;
  delete full.continue;
  if (!ctx?.reportInput) {
    delete full.input;
  }
  return full;
}
__name(finalizeIssue2, "finalizeIssue");
function getSizableOrigin2(input) {
  if (input instanceof Set) return "set";
  if (input instanceof Map) return "map";
  if (input instanceof File) return "file";
  return "unknown";
}
__name(getSizableOrigin2, "getSizableOrigin");
function getLengthableOrigin2(input) {
  if (Array.isArray(input)) return "array";
  if (typeof input === "string") return "string";
  return "unknown";
}
__name(getLengthableOrigin2, "getLengthableOrigin");
function issue2(...args) {
  const [iss, input, inst] = args;
  if (typeof iss === "string") {
    return {
      message: iss,
      code: "custom",
      input,
      inst
    };
  }
  return {
    ...iss
  };
}
__name(issue2, "issue");
function cleanEnum2(obj) {
  return Object.entries(obj).filter(([k, _]) => {
    return Number.isNaN(Number.parseInt(k, 10));
  }).map((el) => el[1]);
}
__name(cleanEnum2, "cleanEnum");
function base64ToUint8Array(base643) {
  const binaryString = atob(base643);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
__name(base64ToUint8Array, "base64ToUint8Array");
function uint8ArrayToBase64(bytes) {
  let binaryString = "";
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}
__name(uint8ArrayToBase64, "uint8ArrayToBase64");
function base64urlToUint8Array(base64url2) {
  const base643 = base64url2.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - base643.length % 4) % 4);
  return base64ToUint8Array(base643 + padding);
}
__name(base64urlToUint8Array, "base64urlToUint8Array");
function uint8ArrayToBase64url(bytes) {
  return uint8ArrayToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
__name(uint8ArrayToBase64url, "uint8ArrayToBase64url");
function hexToUint8Array(hex2) {
  const cleanHex = hex2.replace(/^0x/, "");
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(cleanHex.slice(i, i + 2), 16);
  }
  return bytes;
}
__name(hexToUint8Array, "hexToUint8Array");
function uint8ArrayToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(uint8ArrayToHex, "uint8ArrayToHex");
var Class2 = class {
  static {
    __name(this, "Class");
  }
  constructor(..._args) {
  }
};

// node_modules/zod/v4/core/errors.js
var initializer = /* @__PURE__ */ __name((inst, def) => {
  inst.name = "$ZodError";
  Object.defineProperty(inst, "_zod", {
    value: inst._zod,
    enumerable: false
  });
  Object.defineProperty(inst, "issues", {
    value: def,
    enumerable: false
  });
  inst.message = JSON.stringify(def, jsonStringifyReplacer2, 2);
  Object.defineProperty(inst, "toString", {
    value: /* @__PURE__ */ __name(() => inst.message, "value"),
    enumerable: false
  });
}, "initializer");
var $ZodError = $constructor("$ZodError", initializer);
var $ZodRealError = $constructor("$ZodError", initializer, {
  Parent: Error
});
function flattenError(error3, mapper = (issue3) => issue3.message) {
  const fieldErrors = {};
  const formErrors = [];
  for (const sub of error3.issues) {
    if (sub.path.length > 0) {
      fieldErrors[sub.path[0]] = fieldErrors[sub.path[0]] || [];
      fieldErrors[sub.path[0]].push(mapper(sub));
    } else {
      formErrors.push(mapper(sub));
    }
  }
  return {
    formErrors,
    fieldErrors
  };
}
__name(flattenError, "flattenError");
function formatError(error3, mapper = (issue3) => issue3.message) {
  const fieldErrors = {
    _errors: []
  };
  const processError = /* @__PURE__ */ __name((error4) => {
    for (const issue3 of error4.issues) {
      if (issue3.code === "invalid_union" && issue3.errors.length) {
        issue3.errors.map((issues) => processError({
          issues
        }));
      } else if (issue3.code === "invalid_key") {
        processError({
          issues: issue3.issues
        });
      } else if (issue3.code === "invalid_element") {
        processError({
          issues: issue3.issues
        });
      } else if (issue3.path.length === 0) {
        fieldErrors._errors.push(mapper(issue3));
      } else {
        let curr = fieldErrors;
        let i = 0;
        while (i < issue3.path.length) {
          const el = issue3.path[i];
          const terminal = i === issue3.path.length - 1;
          if (!terminal) {
            curr[el] = curr[el] || {
              _errors: []
            };
          } else {
            curr[el] = curr[el] || {
              _errors: []
            };
            curr[el]._errors.push(mapper(issue3));
          }
          curr = curr[el];
          i++;
        }
      }
    }
  }, "processError");
  processError(error3);
  return fieldErrors;
}
__name(formatError, "formatError");

// node_modules/zod/v4/core/parse.js
var _parse = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx, _params) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    async: false
  }) : {
    async: false
  };
  const result = schema3._zod.run({
    value,
    issues: []
  }, ctx);
  if (result instanceof Promise) {
    throw new $ZodAsyncError();
  }
  if (result.issues.length) {
    const e = new (_params?.Err ?? _Err)(result.issues.map((iss) => finalizeIssue2(iss, ctx, config())));
    captureStackTrace2(e, _params?.callee);
    throw e;
  }
  return result.value;
}, "_parse");
var _parseAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx, params) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    async: true
  }) : {
    async: true
  };
  let result = schema3._zod.run({
    value,
    issues: []
  }, ctx);
  if (result instanceof Promise) result = await result;
  if (result.issues.length) {
    const e = new (params?.Err ?? _Err)(result.issues.map((iss) => finalizeIssue2(iss, ctx, config())));
    captureStackTrace2(e, params?.callee);
    throw e;
  }
  return result.value;
}, "_parseAsync");
var _safeParse = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx) => {
  const ctx = _ctx ? {
    ..._ctx,
    async: false
  } : {
    async: false
  };
  const result = schema3._zod.run({
    value,
    issues: []
  }, ctx);
  if (result instanceof Promise) {
    throw new $ZodAsyncError();
  }
  return result.issues.length ? {
    success: false,
    error: new (_Err ?? $ZodError)(result.issues.map((iss) => finalizeIssue2(iss, ctx, config())))
  } : {
    success: true,
    data: result.value
  };
}, "_safeParse");
var safeParse = /* @__PURE__ */ _safeParse($ZodRealError);
var _safeParseAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    async: true
  }) : {
    async: true
  };
  let result = schema3._zod.run({
    value,
    issues: []
  }, ctx);
  if (result instanceof Promise) result = await result;
  return result.issues.length ? {
    success: false,
    error: new _Err(result.issues.map((iss) => finalizeIssue2(iss, ctx, config())))
  } : {
    success: true,
    data: result.value
  };
}, "_safeParseAsync");
var safeParseAsync = /* @__PURE__ */ _safeParseAsync($ZodRealError);
var _encode = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    direction: "backward"
  }) : {
    direction: "backward"
  };
  return _parse(_Err)(schema3, value, ctx);
}, "_encode");
var _decode = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx) => {
  return _parse(_Err)(schema3, value, _ctx);
}, "_decode");
var _encodeAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    direction: "backward"
  }) : {
    direction: "backward"
  };
  return _parseAsync(_Err)(schema3, value, ctx);
}, "_encodeAsync");
var _decodeAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx) => {
  return _parseAsync(_Err)(schema3, value, _ctx);
}, "_decodeAsync");
var _safeEncode = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    direction: "backward"
  }) : {
    direction: "backward"
  };
  return _safeParse(_Err)(schema3, value, ctx);
}, "_safeEncode");
var _safeDecode = /* @__PURE__ */ __name((_Err) => (schema3, value, _ctx) => {
  return _safeParse(_Err)(schema3, value, _ctx);
}, "_safeDecode");
var _safeEncodeAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx) => {
  const ctx = _ctx ? Object.assign(_ctx, {
    direction: "backward"
  }) : {
    direction: "backward"
  };
  return _safeParseAsync(_Err)(schema3, value, ctx);
}, "_safeEncodeAsync");
var _safeDecodeAsync = /* @__PURE__ */ __name((_Err) => async (schema3, value, _ctx) => {
  return _safeParseAsync(_Err)(schema3, value, _ctx);
}, "_safeDecodeAsync");

// node_modules/zod/v4/core/regexes.js
var cuid = /^[cC][^\s-]{8,}$/;
var cuid2 = /^[0-9a-z]+$/;
var ulid = /^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}$/;
var xid = /^[0-9a-vA-V]{20}$/;
var ksuid = /^[A-Za-z0-9]{27}$/;
var nanoid = /^[a-zA-Z0-9_-]{21}$/;
var duration = /^P(?:(\d+W)|(?!.*W)(?=\d|T\d)(\d+Y)?(\d+M)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+([.,]\d+)?S)?)?)$/;
var guid = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;
var uuid = /* @__PURE__ */ __name((version2) => {
  if (!version2) return /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/;
  return new RegExp(`^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-${version2}[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$`);
}, "uuid");
var email = /^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$/;
var _emoji = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
function emoji() {
  return new RegExp(_emoji, "u");
}
__name(emoji, "emoji");
var ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
var cidrv4 = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/([0-9]|[1-2][0-9]|3[0-2])$/;
var cidrv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:?){0,6})\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64 = /^$|^(?:[0-9a-zA-Z+/]{4})*(?:(?:[0-9a-zA-Z+/]{2}==)|(?:[0-9a-zA-Z+/]{3}=))?$/;
var base64url = /^[A-Za-z0-9_-]*$/;
var hostname = /^(?=.{1,253}\.?$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[-0-9a-zA-Z]{0,61}[0-9a-zA-Z])?)*\.?$/;
var e164 = /^\+(?:[0-9]){6,14}[0-9]$/;
var dateSource = `(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))`;
var date = /* @__PURE__ */ new RegExp(`^${dateSource}$`);
function timeSource(args) {
  const hhmm = `(?:[01]\\d|2[0-3]):[0-5]\\d`;
  const regex = typeof args.precision === "number" ? args.precision === -1 ? `${hhmm}` : args.precision === 0 ? `${hhmm}:[0-5]\\d` : `${hhmm}:[0-5]\\d\\.\\d{${args.precision}}` : `${hhmm}(?::[0-5]\\d(?:\\.\\d+)?)?`;
  return regex;
}
__name(timeSource, "timeSource");
function time(args) {
  return new RegExp(`^${timeSource(args)}$`);
}
__name(time, "time");
function datetime(args) {
  const time3 = timeSource({
    precision: args.precision
  });
  const opts = [
    "Z"
  ];
  if (args.local) opts.push("");
  if (args.offset) opts.push(`([+-](?:[01]\\d|2[0-3]):[0-5]\\d)`);
  const timeRegex = `${time3}(?:${opts.join("|")})`;
  return new RegExp(`^${dateSource}T(?:${timeRegex})$`);
}
__name(datetime, "datetime");
var string = /* @__PURE__ */ __name((params) => {
  const regex = params ? `[\\s\\S]{${params?.minimum ?? 0},${params?.maximum ?? ""}}` : `[\\s\\S]*`;
  return new RegExp(`^${regex}$`);
}, "string");
var bigint = /^-?\d+n?$/;
var integer = /^-?\d+$/;
var number = /^-?\d+(?:\.\d+)?/;
var boolean = /^(?:true|false)$/i;
var lowercase = /^[^A-Z]*$/;
var uppercase = /^[^a-z]*$/;

// node_modules/zod/v4/core/checks.js
var $ZodCheck = /* @__PURE__ */ $constructor("$ZodCheck", (inst, def) => {
  var _a;
  inst._zod ?? (inst._zod = {});
  inst._zod.def = def;
  (_a = inst._zod).onattach ?? (_a.onattach = []);
});
var numericOriginMap = {
  number: "number",
  bigint: "bigint",
  object: "date"
};
var $ZodCheckLessThan = /* @__PURE__ */ $constructor("$ZodCheckLessThan", (inst, def) => {
  $ZodCheck.init(inst, def);
  const origin = numericOriginMap[typeof def.value];
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    const curr = (def.inclusive ? bag.maximum : bag.exclusiveMaximum) ?? Number.POSITIVE_INFINITY;
    if (def.value < curr) {
      if (def.inclusive) bag.maximum = def.value;
      else bag.exclusiveMaximum = def.value;
    }
  });
  inst._zod.check = (payload) => {
    if (def.inclusive ? payload.value <= def.value : payload.value < def.value) {
      return;
    }
    payload.issues.push({
      origin,
      code: "too_big",
      maximum: def.value,
      input: payload.value,
      inclusive: def.inclusive,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckGreaterThan = /* @__PURE__ */ $constructor("$ZodCheckGreaterThan", (inst, def) => {
  $ZodCheck.init(inst, def);
  const origin = numericOriginMap[typeof def.value];
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    const curr = (def.inclusive ? bag.minimum : bag.exclusiveMinimum) ?? Number.NEGATIVE_INFINITY;
    if (def.value > curr) {
      if (def.inclusive) bag.minimum = def.value;
      else bag.exclusiveMinimum = def.value;
    }
  });
  inst._zod.check = (payload) => {
    if (def.inclusive ? payload.value >= def.value : payload.value > def.value) {
      return;
    }
    payload.issues.push({
      origin,
      code: "too_small",
      minimum: def.value,
      input: payload.value,
      inclusive: def.inclusive,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckMultipleOf = /* @__PURE__ */ $constructor("$ZodCheckMultipleOf", (inst, def) => {
  $ZodCheck.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    var _a;
    (_a = inst2._zod.bag).multipleOf ?? (_a.multipleOf = def.value);
  });
  inst._zod.check = (payload) => {
    if (typeof payload.value !== typeof def.value) throw new Error("Cannot mix number and bigint in multiple_of check.");
    const isMultiple = typeof payload.value === "bigint" ? payload.value % def.value === BigInt(0) : floatSafeRemainder2(payload.value, def.value) === 0;
    if (isMultiple) return;
    payload.issues.push({
      origin: typeof payload.value,
      code: "not_multiple_of",
      divisor: def.value,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckNumberFormat = /* @__PURE__ */ $constructor("$ZodCheckNumberFormat", (inst, def) => {
  $ZodCheck.init(inst, def);
  def.format = def.format || "float64";
  const isInt = def.format?.includes("int");
  const origin = isInt ? "int" : "number";
  const [minimum, maximum] = NUMBER_FORMAT_RANGES2[def.format];
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.format = def.format;
    bag.minimum = minimum;
    bag.maximum = maximum;
    if (isInt) bag.pattern = integer;
  });
  inst._zod.check = (payload) => {
    const input = payload.value;
    if (isInt) {
      if (!Number.isInteger(input)) {
        payload.issues.push({
          expected: origin,
          format: def.format,
          code: "invalid_type",
          continue: false,
          input,
          inst
        });
        return;
      }
      if (!Number.isSafeInteger(input)) {
        if (input > 0) {
          payload.issues.push({
            input,
            code: "too_big",
            maximum: Number.MAX_SAFE_INTEGER,
            note: "Integers must be within the safe integer range.",
            inst,
            origin,
            continue: !def.abort
          });
        } else {
          payload.issues.push({
            input,
            code: "too_small",
            minimum: Number.MIN_SAFE_INTEGER,
            note: "Integers must be within the safe integer range.",
            inst,
            origin,
            continue: !def.abort
          });
        }
        return;
      }
    }
    if (input < minimum) {
      payload.issues.push({
        origin: "number",
        input,
        code: "too_small",
        minimum,
        inclusive: true,
        inst,
        continue: !def.abort
      });
    }
    if (input > maximum) {
      payload.issues.push({
        origin: "number",
        input,
        code: "too_big",
        maximum,
        inst
      });
    }
  };
});
var $ZodCheckMaxLength = /* @__PURE__ */ $constructor("$ZodCheckMaxLength", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = (payload) => {
    const val = payload.value;
    return !nullish2(val) && val.length !== void 0;
  });
  inst._zod.onattach.push((inst2) => {
    const curr = inst2._zod.bag.maximum ?? Number.POSITIVE_INFINITY;
    if (def.maximum < curr) inst2._zod.bag.maximum = def.maximum;
  });
  inst._zod.check = (payload) => {
    const input = payload.value;
    const length = input.length;
    if (length <= def.maximum) return;
    const origin = getLengthableOrigin2(input);
    payload.issues.push({
      origin,
      code: "too_big",
      maximum: def.maximum,
      inclusive: true,
      input,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckMinLength = /* @__PURE__ */ $constructor("$ZodCheckMinLength", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = (payload) => {
    const val = payload.value;
    return !nullish2(val) && val.length !== void 0;
  });
  inst._zod.onattach.push((inst2) => {
    const curr = inst2._zod.bag.minimum ?? Number.NEGATIVE_INFINITY;
    if (def.minimum > curr) inst2._zod.bag.minimum = def.minimum;
  });
  inst._zod.check = (payload) => {
    const input = payload.value;
    const length = input.length;
    if (length >= def.minimum) return;
    const origin = getLengthableOrigin2(input);
    payload.issues.push({
      origin,
      code: "too_small",
      minimum: def.minimum,
      inclusive: true,
      input,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckLengthEquals = /* @__PURE__ */ $constructor("$ZodCheckLengthEquals", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = (payload) => {
    const val = payload.value;
    return !nullish2(val) && val.length !== void 0;
  });
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.minimum = def.length;
    bag.maximum = def.length;
    bag.length = def.length;
  });
  inst._zod.check = (payload) => {
    const input = payload.value;
    const length = input.length;
    if (length === def.length) return;
    const origin = getLengthableOrigin2(input);
    const tooBig = length > def.length;
    payload.issues.push({
      origin,
      ...tooBig ? {
        code: "too_big",
        maximum: def.length
      } : {
        code: "too_small",
        minimum: def.length
      },
      inclusive: true,
      exact: true,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckStringFormat = /* @__PURE__ */ $constructor("$ZodCheckStringFormat", (inst, def) => {
  var _a, _b;
  $ZodCheck.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.format = def.format;
    if (def.pattern) {
      bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
      bag.patterns.add(def.pattern);
    }
  });
  if (def.pattern) (_a = inst._zod).check ?? (_a.check = (payload) => {
    def.pattern.lastIndex = 0;
    if (def.pattern.test(payload.value)) return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: def.format,
      input: payload.value,
      ...def.pattern ? {
        pattern: def.pattern.toString()
      } : {},
      inst,
      continue: !def.abort
    });
  });
  else (_b = inst._zod).check ?? (_b.check = () => {
  });
});
var $ZodCheckRegex = /* @__PURE__ */ $constructor("$ZodCheckRegex", (inst, def) => {
  $ZodCheckStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    def.pattern.lastIndex = 0;
    if (def.pattern.test(payload.value)) return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "regex",
      input: payload.value,
      pattern: def.pattern.toString(),
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckLowerCase = /* @__PURE__ */ $constructor("$ZodCheckLowerCase", (inst, def) => {
  def.pattern ?? (def.pattern = lowercase);
  $ZodCheckStringFormat.init(inst, def);
});
var $ZodCheckUpperCase = /* @__PURE__ */ $constructor("$ZodCheckUpperCase", (inst, def) => {
  def.pattern ?? (def.pattern = uppercase);
  $ZodCheckStringFormat.init(inst, def);
});
var $ZodCheckIncludes = /* @__PURE__ */ $constructor("$ZodCheckIncludes", (inst, def) => {
  $ZodCheck.init(inst, def);
  const escapedRegex = escapeRegex2(def.includes);
  const pattern = new RegExp(typeof def.position === "number" ? `^.{${def.position}}${escapedRegex}` : escapedRegex);
  def.pattern = pattern;
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
    bag.patterns.add(pattern);
  });
  inst._zod.check = (payload) => {
    if (payload.value.includes(def.includes, def.position)) return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "includes",
      includes: def.includes,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckStartsWith = /* @__PURE__ */ $constructor("$ZodCheckStartsWith", (inst, def) => {
  $ZodCheck.init(inst, def);
  const pattern = new RegExp(`^${escapeRegex2(def.prefix)}.*`);
  def.pattern ?? (def.pattern = pattern);
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
    bag.patterns.add(pattern);
  });
  inst._zod.check = (payload) => {
    if (payload.value.startsWith(def.prefix)) return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "starts_with",
      prefix: def.prefix,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckEndsWith = /* @__PURE__ */ $constructor("$ZodCheckEndsWith", (inst, def) => {
  $ZodCheck.init(inst, def);
  const pattern = new RegExp(`.*${escapeRegex2(def.suffix)}$`);
  def.pattern ?? (def.pattern = pattern);
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
    bag.patterns.add(pattern);
  });
  inst._zod.check = (payload) => {
    if (payload.value.endsWith(def.suffix)) return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "ends_with",
      suffix: def.suffix,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckOverwrite = /* @__PURE__ */ $constructor("$ZodCheckOverwrite", (inst, def) => {
  $ZodCheck.init(inst, def);
  inst._zod.check = (payload) => {
    payload.value = def.tx(payload.value);
  };
});

// node_modules/zod/v4/core/doc.js
var Doc = class {
  static {
    __name(this, "Doc");
  }
  constructor(args = []) {
    this.content = [];
    this.indent = 0;
    if (this) this.args = args;
  }
  indented(fn) {
    this.indent += 1;
    fn(this);
    this.indent -= 1;
  }
  write(arg) {
    if (typeof arg === "function") {
      arg(this, {
        execution: "sync"
      });
      arg(this, {
        execution: "async"
      });
      return;
    }
    const content = arg;
    const lines = content.split("\n").filter((x) => x);
    const minIndent = Math.min(...lines.map((x) => x.length - x.trimStart().length));
    const dedented = lines.map((x) => x.slice(minIndent)).map((x) => " ".repeat(this.indent * 2) + x);
    for (const line2 of dedented) {
      this.content.push(line2);
    }
  }
  compile() {
    const F = Function;
    const args = this?.args;
    const content = this?.content ?? [
      ``
    ];
    const lines = [
      ...content.map((x) => `  ${x}`)
    ];
    return new F(...args, lines.join("\n"));
  }
};

// node_modules/zod/v4/core/versions.js
var version = {
  major: 4,
  minor: 1,
  patch: 12
};

// node_modules/zod/v4/core/schemas.js
var $ZodType = /* @__PURE__ */ $constructor("$ZodType", (inst, def) => {
  var _a;
  inst ?? (inst = {});
  inst._zod.def = def;
  inst._zod.bag = inst._zod.bag || {};
  inst._zod.version = version;
  const checks = [
    ...inst._zod.def.checks ?? []
  ];
  if (inst._zod.traits.has("$ZodCheck")) {
    checks.unshift(inst);
  }
  for (const ch of checks) {
    for (const fn of ch._zod.onattach) {
      fn(inst);
    }
  }
  if (checks.length === 0) {
    (_a = inst._zod).deferred ?? (_a.deferred = []);
    inst._zod.deferred?.push(() => {
      inst._zod.run = inst._zod.parse;
    });
  } else {
    const runChecks = /* @__PURE__ */ __name((payload, checks2, ctx) => {
      let isAborted = aborted2(payload);
      let asyncResult;
      for (const ch of checks2) {
        if (ch._zod.def.when) {
          const shouldRun = ch._zod.def.when(payload);
          if (!shouldRun) continue;
        } else if (isAborted) {
          continue;
        }
        const currLen = payload.issues.length;
        const _ = ch._zod.check(payload);
        if (_ instanceof Promise && ctx?.async === false) {
          throw new $ZodAsyncError();
        }
        if (asyncResult || _ instanceof Promise) {
          asyncResult = (asyncResult ?? Promise.resolve()).then(async () => {
            await _;
            const nextLen = payload.issues.length;
            if (nextLen === currLen) return;
            if (!isAborted) isAborted = aborted2(payload, currLen);
          });
        } else {
          const nextLen = payload.issues.length;
          if (nextLen === currLen) continue;
          if (!isAborted) isAborted = aborted2(payload, currLen);
        }
      }
      if (asyncResult) {
        return asyncResult.then(() => {
          return payload;
        });
      }
      return payload;
    }, "runChecks");
    const handleCanaryResult = /* @__PURE__ */ __name((canary, payload, ctx) => {
      if (aborted2(canary)) {
        canary.aborted = true;
        return canary;
      }
      const checkResult = runChecks(payload, checks, ctx);
      if (checkResult instanceof Promise) {
        if (ctx.async === false) throw new $ZodAsyncError();
        return checkResult.then((checkResult2) => inst._zod.parse(checkResult2, ctx));
      }
      return inst._zod.parse(checkResult, ctx);
    }, "handleCanaryResult");
    inst._zod.run = (payload, ctx) => {
      if (ctx.skipChecks) {
        return inst._zod.parse(payload, ctx);
      }
      if (ctx.direction === "backward") {
        const canary = inst._zod.parse({
          value: payload.value,
          issues: []
        }, {
          ...ctx,
          skipChecks: true
        });
        if (canary instanceof Promise) {
          return canary.then((canary2) => {
            return handleCanaryResult(canary2, payload, ctx);
          });
        }
        return handleCanaryResult(canary, payload, ctx);
      }
      const result = inst._zod.parse(payload, ctx);
      if (result instanceof Promise) {
        if (ctx.async === false) throw new $ZodAsyncError();
        return result.then((result2) => runChecks(result2, checks, ctx));
      }
      return runChecks(result, checks, ctx);
    };
  }
  inst["~standard"] = {
    validate: /* @__PURE__ */ __name((value) => {
      try {
        const r = safeParse(inst, value);
        return r.success ? {
          value: r.data
        } : {
          issues: r.error?.issues
        };
      } catch (_) {
        return safeParseAsync(inst, value).then((r) => r.success ? {
          value: r.data
        } : {
          issues: r.error?.issues
        });
      }
    }, "validate"),
    vendor: "zod",
    version: 1
  };
});
var $ZodString = /* @__PURE__ */ $constructor("$ZodString", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = [
    ...inst?._zod.bag?.patterns ?? []
  ].pop() ?? string(inst._zod.bag);
  inst._zod.parse = (payload, _) => {
    if (def.coerce) try {
      payload.value = String(payload.value);
    } catch (_2) {
    }
    if (typeof payload.value === "string") return payload;
    payload.issues.push({
      expected: "string",
      code: "invalid_type",
      input: payload.value,
      inst
    });
    return payload;
  };
});
var $ZodStringFormat = /* @__PURE__ */ $constructor("$ZodStringFormat", (inst, def) => {
  $ZodCheckStringFormat.init(inst, def);
  $ZodString.init(inst, def);
});
var $ZodGUID = /* @__PURE__ */ $constructor("$ZodGUID", (inst, def) => {
  def.pattern ?? (def.pattern = guid);
  $ZodStringFormat.init(inst, def);
});
var $ZodUUID = /* @__PURE__ */ $constructor("$ZodUUID", (inst, def) => {
  if (def.version) {
    const versionMap = {
      v1: 1,
      v2: 2,
      v3: 3,
      v4: 4,
      v5: 5,
      v6: 6,
      v7: 7,
      v8: 8
    };
    const v = versionMap[def.version];
    if (v === void 0) throw new Error(`Invalid UUID version: "${def.version}"`);
    def.pattern ?? (def.pattern = uuid(v));
  } else def.pattern ?? (def.pattern = uuid());
  $ZodStringFormat.init(inst, def);
});
var $ZodEmail = /* @__PURE__ */ $constructor("$ZodEmail", (inst, def) => {
  def.pattern ?? (def.pattern = email);
  $ZodStringFormat.init(inst, def);
});
var $ZodURL = /* @__PURE__ */ $constructor("$ZodURL", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    try {
      const trimmed = payload.value.trim();
      const url = new URL(trimmed);
      if (def.hostname) {
        def.hostname.lastIndex = 0;
        if (!def.hostname.test(url.hostname)) {
          payload.issues.push({
            code: "invalid_format",
            format: "url",
            note: "Invalid hostname",
            pattern: hostname.source,
            input: payload.value,
            inst,
            continue: !def.abort
          });
        }
      }
      if (def.protocol) {
        def.protocol.lastIndex = 0;
        if (!def.protocol.test(url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol)) {
          payload.issues.push({
            code: "invalid_format",
            format: "url",
            note: "Invalid protocol",
            pattern: def.protocol.source,
            input: payload.value,
            inst,
            continue: !def.abort
          });
        }
      }
      if (def.normalize) {
        payload.value = url.href;
      } else {
        payload.value = trimmed;
      }
      return;
    } catch (_) {
      payload.issues.push({
        code: "invalid_format",
        format: "url",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
var $ZodEmoji = /* @__PURE__ */ $constructor("$ZodEmoji", (inst, def) => {
  def.pattern ?? (def.pattern = emoji());
  $ZodStringFormat.init(inst, def);
});
var $ZodNanoID = /* @__PURE__ */ $constructor("$ZodNanoID", (inst, def) => {
  def.pattern ?? (def.pattern = nanoid);
  $ZodStringFormat.init(inst, def);
});
var $ZodCUID = /* @__PURE__ */ $constructor("$ZodCUID", (inst, def) => {
  def.pattern ?? (def.pattern = cuid);
  $ZodStringFormat.init(inst, def);
});
var $ZodCUID2 = /* @__PURE__ */ $constructor("$ZodCUID2", (inst, def) => {
  def.pattern ?? (def.pattern = cuid2);
  $ZodStringFormat.init(inst, def);
});
var $ZodULID = /* @__PURE__ */ $constructor("$ZodULID", (inst, def) => {
  def.pattern ?? (def.pattern = ulid);
  $ZodStringFormat.init(inst, def);
});
var $ZodXID = /* @__PURE__ */ $constructor("$ZodXID", (inst, def) => {
  def.pattern ?? (def.pattern = xid);
  $ZodStringFormat.init(inst, def);
});
var $ZodKSUID = /* @__PURE__ */ $constructor("$ZodKSUID", (inst, def) => {
  def.pattern ?? (def.pattern = ksuid);
  $ZodStringFormat.init(inst, def);
});
var $ZodISODateTime = /* @__PURE__ */ $constructor("$ZodISODateTime", (inst, def) => {
  def.pattern ?? (def.pattern = datetime(def));
  $ZodStringFormat.init(inst, def);
});
var $ZodISODate = /* @__PURE__ */ $constructor("$ZodISODate", (inst, def) => {
  def.pattern ?? (def.pattern = date);
  $ZodStringFormat.init(inst, def);
});
var $ZodISOTime = /* @__PURE__ */ $constructor("$ZodISOTime", (inst, def) => {
  def.pattern ?? (def.pattern = time(def));
  $ZodStringFormat.init(inst, def);
});
var $ZodISODuration = /* @__PURE__ */ $constructor("$ZodISODuration", (inst, def) => {
  def.pattern ?? (def.pattern = duration);
  $ZodStringFormat.init(inst, def);
});
var $ZodIPv4 = /* @__PURE__ */ $constructor("$ZodIPv4", (inst, def) => {
  def.pattern ?? (def.pattern = ipv4);
  $ZodStringFormat.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.format = `ipv4`;
  });
});
var $ZodIPv6 = /* @__PURE__ */ $constructor("$ZodIPv6", (inst, def) => {
  def.pattern ?? (def.pattern = ipv6);
  $ZodStringFormat.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    const bag = inst2._zod.bag;
    bag.format = `ipv6`;
  });
  inst._zod.check = (payload) => {
    try {
      new URL(`http://[${payload.value}]`);
    } catch {
      payload.issues.push({
        code: "invalid_format",
        format: "ipv6",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
var $ZodCIDRv4 = /* @__PURE__ */ $constructor("$ZodCIDRv4", (inst, def) => {
  def.pattern ?? (def.pattern = cidrv4);
  $ZodStringFormat.init(inst, def);
});
var $ZodCIDRv6 = /* @__PURE__ */ $constructor("$ZodCIDRv6", (inst, def) => {
  def.pattern ?? (def.pattern = cidrv6);
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    const parts = payload.value.split("/");
    try {
      if (parts.length !== 2) throw new Error();
      const [address, prefix] = parts;
      if (!prefix) throw new Error();
      const prefixNum = Number(prefix);
      if (`${prefixNum}` !== prefix) throw new Error();
      if (prefixNum < 0 || prefixNum > 128) throw new Error();
      new URL(`http://[${address}]`);
    } catch {
      payload.issues.push({
        code: "invalid_format",
        format: "cidrv6",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
function isValidBase64(data) {
  if (data === "") return true;
  if (data.length % 4 !== 0) return false;
  try {
    atob(data);
    return true;
  } catch {
    return false;
  }
}
__name(isValidBase64, "isValidBase64");
var $ZodBase64 = /* @__PURE__ */ $constructor("$ZodBase64", (inst, def) => {
  def.pattern ?? (def.pattern = base64);
  $ZodStringFormat.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    inst2._zod.bag.contentEncoding = "base64";
  });
  inst._zod.check = (payload) => {
    if (isValidBase64(payload.value)) return;
    payload.issues.push({
      code: "invalid_format",
      format: "base64",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
function isValidBase64URL(data) {
  if (!base64url.test(data)) return false;
  const base643 = data.replace(/[-_]/g, (c) => c === "-" ? "+" : "/");
  const padded = base643.padEnd(Math.ceil(base643.length / 4) * 4, "=");
  return isValidBase64(padded);
}
__name(isValidBase64URL, "isValidBase64URL");
var $ZodBase64URL = /* @__PURE__ */ $constructor("$ZodBase64URL", (inst, def) => {
  def.pattern ?? (def.pattern = base64url);
  $ZodStringFormat.init(inst, def);
  inst._zod.onattach.push((inst2) => {
    inst2._zod.bag.contentEncoding = "base64url";
  });
  inst._zod.check = (payload) => {
    if (isValidBase64URL(payload.value)) return;
    payload.issues.push({
      code: "invalid_format",
      format: "base64url",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodE164 = /* @__PURE__ */ $constructor("$ZodE164", (inst, def) => {
  def.pattern ?? (def.pattern = e164);
  $ZodStringFormat.init(inst, def);
});
function isValidJWT(token, algorithm2 = null) {
  try {
    const tokensParts = token.split(".");
    if (tokensParts.length !== 3) return false;
    const [header] = tokensParts;
    if (!header) return false;
    const parsedHeader = JSON.parse(atob(header));
    if ("typ" in parsedHeader && parsedHeader?.typ !== "JWT") return false;
    if (!parsedHeader.alg) return false;
    if (algorithm2 && (!("alg" in parsedHeader) || parsedHeader.alg !== algorithm2)) return false;
    return true;
  } catch {
    return false;
  }
}
__name(isValidJWT, "isValidJWT");
var $ZodJWT = /* @__PURE__ */ $constructor("$ZodJWT", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (isValidJWT(payload.value, def.alg)) return;
    payload.issues.push({
      code: "invalid_format",
      format: "jwt",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodNumber = /* @__PURE__ */ $constructor("$ZodNumber", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = inst._zod.bag.pattern ?? number;
  inst._zod.parse = (payload, _ctx) => {
    if (def.coerce) try {
      payload.value = Number(payload.value);
    } catch (_) {
    }
    const input = payload.value;
    if (typeof input === "number" && !Number.isNaN(input) && Number.isFinite(input)) {
      return payload;
    }
    const received = typeof input === "number" ? Number.isNaN(input) ? "NaN" : !Number.isFinite(input) ? "Infinity" : void 0 : void 0;
    payload.issues.push({
      expected: "number",
      code: "invalid_type",
      input,
      inst,
      ...received ? {
        received
      } : {}
    });
    return payload;
  };
});
var $ZodNumberFormat = /* @__PURE__ */ $constructor("$ZodNumber", (inst, def) => {
  $ZodCheckNumberFormat.init(inst, def);
  $ZodNumber.init(inst, def);
});
var $ZodBoolean = /* @__PURE__ */ $constructor("$ZodBoolean", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = boolean;
  inst._zod.parse = (payload, _ctx) => {
    if (def.coerce) try {
      payload.value = Boolean(payload.value);
    } catch (_) {
    }
    const input = payload.value;
    if (typeof input === "boolean") return payload;
    payload.issues.push({
      expected: "boolean",
      code: "invalid_type",
      input,
      inst
    });
    return payload;
  };
});
var $ZodBigInt = /* @__PURE__ */ $constructor("$ZodBigInt", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = bigint;
  inst._zod.parse = (payload, _ctx) => {
    if (def.coerce) try {
      payload.value = BigInt(payload.value);
    } catch (_) {
    }
    if (typeof payload.value === "bigint") return payload;
    payload.issues.push({
      expected: "bigint",
      code: "invalid_type",
      input: payload.value,
      inst
    });
    return payload;
  };
});
var $ZodUnknown = /* @__PURE__ */ $constructor("$ZodUnknown", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload) => payload;
});
var $ZodNever = /* @__PURE__ */ $constructor("$ZodNever", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, _ctx) => {
    payload.issues.push({
      expected: "never",
      code: "invalid_type",
      input: payload.value,
      inst
    });
    return payload;
  };
});
var $ZodDate = /* @__PURE__ */ $constructor("$ZodDate", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, _ctx) => {
    if (def.coerce) {
      try {
        payload.value = new Date(payload.value);
      } catch (_err) {
      }
    }
    const input = payload.value;
    const isDate = input instanceof Date;
    const isValidDate = isDate && !Number.isNaN(input.getTime());
    if (isValidDate) return payload;
    payload.issues.push({
      expected: "date",
      code: "invalid_type",
      input,
      ...isDate ? {
        received: "Invalid Date"
      } : {},
      inst
    });
    return payload;
  };
});
function handleArrayResult(result, final, index) {
  if (result.issues.length) {
    final.issues.push(...prefixIssues2(index, result.issues));
  }
  final.value[index] = result.value;
}
__name(handleArrayResult, "handleArrayResult");
var $ZodArray = /* @__PURE__ */ $constructor("$ZodArray", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, ctx) => {
    const input = payload.value;
    if (!Array.isArray(input)) {
      payload.issues.push({
        expected: "array",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    payload.value = Array(input.length);
    const proms = [];
    for (let i = 0; i < input.length; i++) {
      const item = input[i];
      const result = def.element._zod.run({
        value: item,
        issues: []
      }, ctx);
      if (result instanceof Promise) {
        proms.push(result.then((result2) => handleArrayResult(result2, payload, i)));
      } else {
        handleArrayResult(result, payload, i);
      }
    }
    if (proms.length) {
      return Promise.all(proms).then(() => payload);
    }
    return payload;
  };
});
function handlePropertyResult(result, final, key, input) {
  if (result.issues.length) {
    final.issues.push(...prefixIssues2(key, result.issues));
  }
  if (result.value === void 0) {
    if (key in input) {
      final.value[key] = void 0;
    }
  } else {
    final.value[key] = result.value;
  }
}
__name(handlePropertyResult, "handlePropertyResult");
function normalizeDef(def) {
  const keys = Object.keys(def.shape);
  for (const k of keys) {
    if (!def.shape?.[k]?._zod?.traits?.has("$ZodType")) {
      throw new Error(`Invalid element at key "${k}": expected a Zod schema`);
    }
  }
  const okeys = optionalKeys2(def.shape);
  return {
    ...def,
    keys,
    keySet: new Set(keys),
    numKeys: keys.length,
    optionalKeys: new Set(okeys)
  };
}
__name(normalizeDef, "normalizeDef");
function handleCatchall(proms, input, payload, ctx, def, inst) {
  const unrecognized = [];
  const keySet = def.keySet;
  const _catchall = def.catchall._zod;
  const t = _catchall.def.type;
  for (const key of Object.keys(input)) {
    if (keySet.has(key)) continue;
    if (t === "never") {
      unrecognized.push(key);
      continue;
    }
    const r = _catchall.run({
      value: input[key],
      issues: []
    }, ctx);
    if (r instanceof Promise) {
      proms.push(r.then((r2) => handlePropertyResult(r2, payload, key, input)));
    } else {
      handlePropertyResult(r, payload, key, input);
    }
  }
  if (unrecognized.length) {
    payload.issues.push({
      code: "unrecognized_keys",
      keys: unrecognized,
      input,
      inst
    });
  }
  if (!proms.length) return payload;
  return Promise.all(proms).then(() => {
    return payload;
  });
}
__name(handleCatchall, "handleCatchall");
var $ZodObject = /* @__PURE__ */ $constructor("$ZodObject", (inst, def) => {
  $ZodType.init(inst, def);
  const desc = Object.getOwnPropertyDescriptor(def, "shape");
  if (!desc?.get) {
    const sh = def.shape;
    Object.defineProperty(def, "shape", {
      get: /* @__PURE__ */ __name(() => {
        const newSh = {
          ...sh
        };
        Object.defineProperty(def, "shape", {
          value: newSh
        });
        return newSh;
      }, "get")
    });
  }
  const _normalized = cached2(() => normalizeDef(def));
  defineLazy2(inst._zod, "propValues", () => {
    const shape = def.shape;
    const propValues = {};
    for (const key in shape) {
      const field = shape[key]._zod;
      if (field.values) {
        propValues[key] ?? (propValues[key] = /* @__PURE__ */ new Set());
        for (const v of field.values) propValues[key].add(v);
      }
    }
    return propValues;
  });
  const isObject3 = isObject2;
  const catchall = def.catchall;
  let value;
  inst._zod.parse = (payload, ctx) => {
    value ?? (value = _normalized.value);
    const input = payload.value;
    if (!isObject3(input)) {
      payload.issues.push({
        expected: "object",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    payload.value = {};
    const proms = [];
    const shape = value.shape;
    for (const key of value.keys) {
      const el = shape[key];
      const r = el._zod.run({
        value: input[key],
        issues: []
      }, ctx);
      if (r instanceof Promise) {
        proms.push(r.then((r2) => handlePropertyResult(r2, payload, key, input)));
      } else {
        handlePropertyResult(r, payload, key, input);
      }
    }
    if (!catchall) {
      return proms.length ? Promise.all(proms).then(() => payload) : payload;
    }
    return handleCatchall(proms, input, payload, ctx, _normalized.value, inst);
  };
});
var $ZodObjectJIT = /* @__PURE__ */ $constructor("$ZodObjectJIT", (inst, def) => {
  $ZodObject.init(inst, def);
  const superParse = inst._zod.parse;
  const _normalized = cached2(() => normalizeDef(def));
  const generateFastpass = /* @__PURE__ */ __name((shape) => {
    const doc = new Doc([
      "shape",
      "payload",
      "ctx"
    ]);
    const normalized = _normalized.value;
    const parseStr = /* @__PURE__ */ __name((key) => {
      const k = esc2(key);
      return `shape[${k}]._zod.run({ value: input[${k}], issues: [] }, ctx)`;
    }, "parseStr");
    doc.write(`const input = payload.value;`);
    const ids = /* @__PURE__ */ Object.create(null);
    let counter = 0;
    for (const key of normalized.keys) {
      ids[key] = `key_${counter++}`;
    }
    doc.write(`const newResult = {};`);
    for (const key of normalized.keys) {
      const id = ids[key];
      const k = esc2(key);
      doc.write(`const ${id} = ${parseStr(key)};`);
      doc.write(`
        if (${id}.issues.length) {
          payload.issues = payload.issues.concat(${id}.issues.map(iss => ({
            ...iss,
            path: iss.path ? [${k}, ...iss.path] : [${k}]
          })));
        }
        
        
        if (${id}.value === undefined) {
          if (${k} in input) {
            newResult[${k}] = undefined;
          }
        } else {
          newResult[${k}] = ${id}.value;
        }
        
      `);
    }
    doc.write(`payload.value = newResult;`);
    doc.write(`return payload;`);
    const fn = doc.compile();
    return (payload, ctx) => fn(shape, payload, ctx);
  }, "generateFastpass");
  let fastpass;
  const isObject3 = isObject2;
  const jit = !globalConfig.jitless;
  const allowsEval3 = allowsEval2;
  const fastEnabled = jit && allowsEval3.value;
  const catchall = def.catchall;
  let value;
  inst._zod.parse = (payload, ctx) => {
    value ?? (value = _normalized.value);
    const input = payload.value;
    if (!isObject3(input)) {
      payload.issues.push({
        expected: "object",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    if (jit && fastEnabled && ctx?.async === false && ctx.jitless !== true) {
      if (!fastpass) fastpass = generateFastpass(def.shape);
      payload = fastpass(payload, ctx);
      if (!catchall) return payload;
      return handleCatchall([], input, payload, ctx, value, inst);
    }
    return superParse(payload, ctx);
  };
});
function handleUnionResults(results, final, inst, ctx) {
  for (const result of results) {
    if (result.issues.length === 0) {
      final.value = result.value;
      return final;
    }
  }
  const nonaborted = results.filter((r) => !aborted2(r));
  if (nonaborted.length === 1) {
    final.value = nonaborted[0].value;
    return nonaborted[0];
  }
  final.issues.push({
    code: "invalid_union",
    input: final.value,
    inst,
    errors: results.map((result) => result.issues.map((iss) => finalizeIssue2(iss, ctx, config())))
  });
  return final;
}
__name(handleUnionResults, "handleUnionResults");
var $ZodUnion = /* @__PURE__ */ $constructor("$ZodUnion", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "optin", () => def.options.some((o) => o._zod.optin === "optional") ? "optional" : void 0);
  defineLazy2(inst._zod, "optout", () => def.options.some((o) => o._zod.optout === "optional") ? "optional" : void 0);
  defineLazy2(inst._zod, "values", () => {
    if (def.options.every((o) => o._zod.values)) {
      return new Set(def.options.flatMap((option) => Array.from(option._zod.values)));
    }
    return void 0;
  });
  defineLazy2(inst._zod, "pattern", () => {
    if (def.options.every((o) => o._zod.pattern)) {
      const patterns = def.options.map((o) => o._zod.pattern);
      return new RegExp(`^(${patterns.map((p) => cleanRegex2(p.source)).join("|")})$`);
    }
    return void 0;
  });
  const single = def.options.length === 1;
  const first = def.options[0]._zod.run;
  inst._zod.parse = (payload, ctx) => {
    if (single) {
      return first(payload, ctx);
    }
    let async = false;
    const results = [];
    for (const option of def.options) {
      const result = option._zod.run({
        value: payload.value,
        issues: []
      }, ctx);
      if (result instanceof Promise) {
        results.push(result);
        async = true;
      } else {
        if (result.issues.length === 0) return result;
        results.push(result);
      }
    }
    if (!async) return handleUnionResults(results, payload, inst, ctx);
    return Promise.all(results).then((results2) => {
      return handleUnionResults(results2, payload, inst, ctx);
    });
  };
});
var $ZodIntersection = /* @__PURE__ */ $constructor("$ZodIntersection", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, ctx) => {
    const input = payload.value;
    const left = def.left._zod.run({
      value: input,
      issues: []
    }, ctx);
    const right = def.right._zod.run({
      value: input,
      issues: []
    }, ctx);
    const async = left instanceof Promise || right instanceof Promise;
    if (async) {
      return Promise.all([
        left,
        right
      ]).then(([left2, right2]) => {
        return handleIntersectionResults(payload, left2, right2);
      });
    }
    return handleIntersectionResults(payload, left, right);
  };
});
function mergeValues(a, b) {
  if (a === b) {
    return {
      valid: true,
      data: a
    };
  }
  if (a instanceof Date && b instanceof Date && +a === +b) {
    return {
      valid: true,
      data: a
    };
  }
  if (isPlainObject2(a) && isPlainObject2(b)) {
    const bKeys = Object.keys(b);
    const sharedKeys = Object.keys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = {
      ...a,
      ...b
    };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return {
          valid: false,
          mergeErrorPath: [
            key,
            ...sharedValue.mergeErrorPath
          ]
        };
      }
      newObj[key] = sharedValue.data;
    }
    return {
      valid: true,
      data: newObj
    };
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) {
      return {
        valid: false,
        mergeErrorPath: []
      };
    }
    const newArray = [];
    for (let index = 0; index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return {
          valid: false,
          mergeErrorPath: [
            index,
            ...sharedValue.mergeErrorPath
          ]
        };
      }
      newArray.push(sharedValue.data);
    }
    return {
      valid: true,
      data: newArray
    };
  }
  return {
    valid: false,
    mergeErrorPath: []
  };
}
__name(mergeValues, "mergeValues");
function handleIntersectionResults(result, left, right) {
  if (left.issues.length) {
    result.issues.push(...left.issues);
  }
  if (right.issues.length) {
    result.issues.push(...right.issues);
  }
  if (aborted2(result)) return result;
  const merged = mergeValues(left.value, right.value);
  if (!merged.valid) {
    throw new Error(`Unmergable intersection. Error path: ${JSON.stringify(merged.mergeErrorPath)}`);
  }
  result.value = merged.data;
  return result;
}
__name(handleIntersectionResults, "handleIntersectionResults");
var $ZodRecord = /* @__PURE__ */ $constructor("$ZodRecord", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, ctx) => {
    const input = payload.value;
    if (!isPlainObject2(input)) {
      payload.issues.push({
        expected: "record",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    const proms = [];
    if (def.keyType._zod.values) {
      const values = def.keyType._zod.values;
      payload.value = {};
      for (const key of values) {
        if (typeof key === "string" || typeof key === "number" || typeof key === "symbol") {
          const result = def.valueType._zod.run({
            value: input[key],
            issues: []
          }, ctx);
          if (result instanceof Promise) {
            proms.push(result.then((result2) => {
              if (result2.issues.length) {
                payload.issues.push(...prefixIssues2(key, result2.issues));
              }
              payload.value[key] = result2.value;
            }));
          } else {
            if (result.issues.length) {
              payload.issues.push(...prefixIssues2(key, result.issues));
            }
            payload.value[key] = result.value;
          }
        }
      }
      let unrecognized;
      for (const key in input) {
        if (!values.has(key)) {
          unrecognized = unrecognized ?? [];
          unrecognized.push(key);
        }
      }
      if (unrecognized && unrecognized.length > 0) {
        payload.issues.push({
          code: "unrecognized_keys",
          input,
          inst,
          keys: unrecognized
        });
      }
    } else {
      payload.value = {};
      for (const key of Reflect.ownKeys(input)) {
        if (key === "__proto__") continue;
        const keyResult = def.keyType._zod.run({
          value: key,
          issues: []
        }, ctx);
        if (keyResult instanceof Promise) {
          throw new Error("Async schemas not supported in object keys currently");
        }
        if (keyResult.issues.length) {
          payload.issues.push({
            code: "invalid_key",
            origin: "record",
            issues: keyResult.issues.map((iss) => finalizeIssue2(iss, ctx, config())),
            input: key,
            path: [
              key
            ],
            inst
          });
          payload.value[keyResult.value] = keyResult.value;
          continue;
        }
        const result = def.valueType._zod.run({
          value: input[key],
          issues: []
        }, ctx);
        if (result instanceof Promise) {
          proms.push(result.then((result2) => {
            if (result2.issues.length) {
              payload.issues.push(...prefixIssues2(key, result2.issues));
            }
            payload.value[keyResult.value] = result2.value;
          }));
        } else {
          if (result.issues.length) {
            payload.issues.push(...prefixIssues2(key, result.issues));
          }
          payload.value[keyResult.value] = result.value;
        }
      }
    }
    if (proms.length) {
      return Promise.all(proms).then(() => payload);
    }
    return payload;
  };
});
var $ZodEnum = /* @__PURE__ */ $constructor("$ZodEnum", (inst, def) => {
  $ZodType.init(inst, def);
  const values = getEnumValues2(def.entries);
  const valuesSet = new Set(values);
  inst._zod.values = valuesSet;
  inst._zod.pattern = new RegExp(`^(${values.filter((k) => propertyKeyTypes2.has(typeof k)).map((o) => typeof o === "string" ? escapeRegex2(o) : o.toString()).join("|")})$`);
  inst._zod.parse = (payload, _ctx) => {
    const input = payload.value;
    if (valuesSet.has(input)) {
      return payload;
    }
    payload.issues.push({
      code: "invalid_value",
      values,
      input,
      inst
    });
    return payload;
  };
});
var $ZodTransform = /* @__PURE__ */ $constructor("$ZodTransform", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      throw new $ZodEncodeError(inst.constructor.name);
    }
    const _out = def.transform(payload.value, payload);
    if (ctx.async) {
      const output = _out instanceof Promise ? _out : Promise.resolve(_out);
      return output.then((output2) => {
        payload.value = output2;
        return payload;
      });
    }
    if (_out instanceof Promise) {
      throw new $ZodAsyncError();
    }
    payload.value = _out;
    return payload;
  };
});
function handleOptionalResult(result, input) {
  if (result.issues.length && input === void 0) {
    return {
      issues: [],
      value: void 0
    };
  }
  return result;
}
__name(handleOptionalResult, "handleOptionalResult");
var $ZodOptional = /* @__PURE__ */ $constructor("$ZodOptional", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "optional";
  inst._zod.optout = "optional";
  defineLazy2(inst._zod, "values", () => {
    return def.innerType._zod.values ? /* @__PURE__ */ new Set([
      ...def.innerType._zod.values,
      void 0
    ]) : void 0;
  });
  defineLazy2(inst._zod, "pattern", () => {
    const pattern = def.innerType._zod.pattern;
    return pattern ? new RegExp(`^(${cleanRegex2(pattern.source)})?$`) : void 0;
  });
  inst._zod.parse = (payload, ctx) => {
    if (def.innerType._zod.optin === "optional") {
      const result = def.innerType._zod.run(payload, ctx);
      if (result instanceof Promise) return result.then((r) => handleOptionalResult(r, payload.value));
      return handleOptionalResult(result, payload.value);
    }
    if (payload.value === void 0) {
      return payload;
    }
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodNullable = /* @__PURE__ */ $constructor("$ZodNullable", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "optin", () => def.innerType._zod.optin);
  defineLazy2(inst._zod, "optout", () => def.innerType._zod.optout);
  defineLazy2(inst._zod, "pattern", () => {
    const pattern = def.innerType._zod.pattern;
    return pattern ? new RegExp(`^(${cleanRegex2(pattern.source)}|null)$`) : void 0;
  });
  defineLazy2(inst._zod, "values", () => {
    return def.innerType._zod.values ? /* @__PURE__ */ new Set([
      ...def.innerType._zod.values,
      null
    ]) : void 0;
  });
  inst._zod.parse = (payload, ctx) => {
    if (payload.value === null) return payload;
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodDefault = /* @__PURE__ */ $constructor("$ZodDefault", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "optional";
  defineLazy2(inst._zod, "values", () => def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    if (payload.value === void 0) {
      payload.value = def.defaultValue;
      return payload;
    }
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then((result2) => handleDefaultResult(result2, def));
    }
    return handleDefaultResult(result, def);
  };
});
function handleDefaultResult(payload, def) {
  if (payload.value === void 0) {
    payload.value = def.defaultValue;
  }
  return payload;
}
__name(handleDefaultResult, "handleDefaultResult");
var $ZodPrefault = /* @__PURE__ */ $constructor("$ZodPrefault", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "optional";
  defineLazy2(inst._zod, "values", () => def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    if (payload.value === void 0) {
      payload.value = def.defaultValue;
    }
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodNonOptional = /* @__PURE__ */ $constructor("$ZodNonOptional", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "values", () => {
    const v = def.innerType._zod.values;
    return v ? new Set([
      ...v
    ].filter((x) => x !== void 0)) : void 0;
  });
  inst._zod.parse = (payload, ctx) => {
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then((result2) => handleNonOptionalResult(result2, inst));
    }
    return handleNonOptionalResult(result, inst);
  };
});
function handleNonOptionalResult(payload, inst) {
  if (!payload.issues.length && payload.value === void 0) {
    payload.issues.push({
      code: "invalid_type",
      expected: "nonoptional",
      input: payload.value,
      inst
    });
  }
  return payload;
}
__name(handleNonOptionalResult, "handleNonOptionalResult");
var $ZodCatch = /* @__PURE__ */ $constructor("$ZodCatch", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "optin", () => def.innerType._zod.optin);
  defineLazy2(inst._zod, "optout", () => def.innerType._zod.optout);
  defineLazy2(inst._zod, "values", () => def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then((result2) => {
        payload.value = result2.value;
        if (result2.issues.length) {
          payload.value = def.catchValue({
            ...payload,
            error: {
              issues: result2.issues.map((iss) => finalizeIssue2(iss, ctx, config()))
            },
            input: payload.value
          });
          payload.issues = [];
        }
        return payload;
      });
    }
    payload.value = result.value;
    if (result.issues.length) {
      payload.value = def.catchValue({
        ...payload,
        error: {
          issues: result.issues.map((iss) => finalizeIssue2(iss, ctx, config()))
        },
        input: payload.value
      });
      payload.issues = [];
    }
    return payload;
  };
});
var $ZodPipe = /* @__PURE__ */ $constructor("$ZodPipe", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "values", () => def.in._zod.values);
  defineLazy2(inst._zod, "optin", () => def.in._zod.optin);
  defineLazy2(inst._zod, "optout", () => def.out._zod.optout);
  defineLazy2(inst._zod, "propValues", () => def.in._zod.propValues);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      const right = def.out._zod.run(payload, ctx);
      if (right instanceof Promise) {
        return right.then((right2) => handlePipeResult(right2, def.in, ctx));
      }
      return handlePipeResult(right, def.in, ctx);
    }
    const left = def.in._zod.run(payload, ctx);
    if (left instanceof Promise) {
      return left.then((left2) => handlePipeResult(left2, def.out, ctx));
    }
    return handlePipeResult(left, def.out, ctx);
  };
});
function handlePipeResult(left, next, ctx) {
  if (left.issues.length) {
    left.aborted = true;
    return left;
  }
  return next._zod.run({
    value: left.value,
    issues: left.issues
  }, ctx);
}
__name(handlePipeResult, "handlePipeResult");
var $ZodReadonly = /* @__PURE__ */ $constructor("$ZodReadonly", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazy2(inst._zod, "propValues", () => def.innerType._zod.propValues);
  defineLazy2(inst._zod, "values", () => def.innerType._zod.values);
  defineLazy2(inst._zod, "optin", () => def.innerType._zod.optin);
  defineLazy2(inst._zod, "optout", () => def.innerType._zod.optout);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then(handleReadonlyResult);
    }
    return handleReadonlyResult(result);
  };
});
function handleReadonlyResult(payload) {
  payload.value = Object.freeze(payload.value);
  return payload;
}
__name(handleReadonlyResult, "handleReadonlyResult");
var $ZodCustom = /* @__PURE__ */ $constructor("$ZodCustom", (inst, def) => {
  $ZodCheck.init(inst, def);
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, _) => {
    return payload;
  };
  inst._zod.check = (payload) => {
    const input = payload.value;
    const r = def.fn(input);
    if (r instanceof Promise) {
      return r.then((r2) => handleRefineResult(r2, payload, input, inst));
    }
    handleRefineResult(r, payload, input, inst);
    return;
  };
});
function handleRefineResult(result, payload, input, inst) {
  if (!result) {
    const _iss = {
      code: "custom",
      input,
      inst,
      path: [
        ...inst._zod.def.path ?? []
      ],
      continue: !inst._zod.def.abort
    };
    if (inst._zod.def.params) _iss.params = inst._zod.def.params;
    payload.issues.push(issue2(_iss));
  }
}
__name(handleRefineResult, "handleRefineResult");

// node_modules/zod/v4/locales/en.js
var parsedType = /* @__PURE__ */ __name((data) => {
  const t = typeof data;
  switch (t) {
    case "number": {
      return Number.isNaN(data) ? "NaN" : "number";
    }
    case "object": {
      if (Array.isArray(data)) {
        return "array";
      }
      if (data === null) {
        return "null";
      }
      if (Object.getPrototypeOf(data) !== Object.prototype && data.constructor) {
        return data.constructor.name;
      }
    }
  }
  return t;
}, "parsedType");
var error = /* @__PURE__ */ __name(() => {
  const Sizable = {
    string: {
      unit: "characters",
      verb: "to have"
    },
    file: {
      unit: "bytes",
      verb: "to have"
    },
    array: {
      unit: "items",
      verb: "to have"
    },
    set: {
      unit: "items",
      verb: "to have"
    }
  };
  function getSizing(origin) {
    return Sizable[origin] ?? null;
  }
  __name(getSizing, "getSizing");
  const Nouns = {
    regex: "input",
    email: "email address",
    url: "URL",
    emoji: "emoji",
    uuid: "UUID",
    uuidv4: "UUIDv4",
    uuidv6: "UUIDv6",
    nanoid: "nanoid",
    guid: "GUID",
    cuid: "cuid",
    cuid2: "cuid2",
    ulid: "ULID",
    xid: "XID",
    ksuid: "KSUID",
    datetime: "ISO datetime",
    date: "ISO date",
    time: "ISO time",
    duration: "ISO duration",
    ipv4: "IPv4 address",
    ipv6: "IPv6 address",
    cidrv4: "IPv4 range",
    cidrv6: "IPv6 range",
    base64: "base64-encoded string",
    base64url: "base64url-encoded string",
    json_string: "JSON string",
    e164: "E.164 number",
    jwt: "JWT",
    template_literal: "input"
  };
  return (issue3) => {
    switch (issue3.code) {
      case "invalid_type":
        return `Invalid input: expected ${issue3.expected}, received ${parsedType(issue3.input)}`;
      case "invalid_value":
        if (issue3.values.length === 1) return `Invalid input: expected ${stringifyPrimitive2(issue3.values[0])}`;
        return `Invalid option: expected one of ${joinValues2(issue3.values, "|")}`;
      case "too_big": {
        const adj = issue3.inclusive ? "<=" : "<";
        const sizing = getSizing(issue3.origin);
        if (sizing) return `Too big: expected ${issue3.origin ?? "value"} to have ${adj}${issue3.maximum.toString()} ${sizing.unit ?? "elements"}`;
        return `Too big: expected ${issue3.origin ?? "value"} to be ${adj}${issue3.maximum.toString()}`;
      }
      case "too_small": {
        const adj = issue3.inclusive ? ">=" : ">";
        const sizing = getSizing(issue3.origin);
        if (sizing) {
          return `Too small: expected ${issue3.origin} to have ${adj}${issue3.minimum.toString()} ${sizing.unit}`;
        }
        return `Too small: expected ${issue3.origin} to be ${adj}${issue3.minimum.toString()}`;
      }
      case "invalid_format": {
        const _issue = issue3;
        if (_issue.format === "starts_with") {
          return `Invalid string: must start with "${_issue.prefix}"`;
        }
        if (_issue.format === "ends_with") return `Invalid string: must end with "${_issue.suffix}"`;
        if (_issue.format === "includes") return `Invalid string: must include "${_issue.includes}"`;
        if (_issue.format === "regex") return `Invalid string: must match pattern ${_issue.pattern}`;
        return `Invalid ${Nouns[_issue.format] ?? issue3.format}`;
      }
      case "not_multiple_of":
        return `Invalid number: must be a multiple of ${issue3.divisor}`;
      case "unrecognized_keys":
        return `Unrecognized key${issue3.keys.length > 1 ? "s" : ""}: ${joinValues2(issue3.keys, ", ")}`;
      case "invalid_key":
        return `Invalid key in ${issue3.origin}`;
      case "invalid_union":
        return "Invalid input";
      case "invalid_element":
        return `Invalid value in ${issue3.origin}`;
      default:
        return `Invalid input`;
    }
  };
}, "error");
function en_default() {
  return {
    localeError: error()
  };
}
__name(en_default, "default");

// node_modules/zod/v4/core/registries.js
var $ZodRegistry = class {
  static {
    __name(this, "$ZodRegistry");
  }
  constructor() {
    this._map = /* @__PURE__ */ new WeakMap();
    this._idmap = /* @__PURE__ */ new Map();
  }
  add(schema3, ..._meta) {
    const meta = _meta[0];
    this._map.set(schema3, meta);
    if (meta && typeof meta === "object" && "id" in meta) {
      if (this._idmap.has(meta.id)) {
        throw new Error(`ID ${meta.id} already exists in the registry`);
      }
      this._idmap.set(meta.id, schema3);
    }
    return this;
  }
  clear() {
    this._map = /* @__PURE__ */ new WeakMap();
    this._idmap = /* @__PURE__ */ new Map();
    return this;
  }
  remove(schema3) {
    const meta = this._map.get(schema3);
    if (meta && typeof meta === "object" && "id" in meta) {
      this._idmap.delete(meta.id);
    }
    this._map.delete(schema3);
    return this;
  }
  get(schema3) {
    const p = schema3._zod.parent;
    if (p) {
      const pm = {
        ...this.get(p) ?? {}
      };
      delete pm.id;
      const f = {
        ...pm,
        ...this._map.get(schema3)
      };
      return Object.keys(f).length ? f : void 0;
    }
    return this._map.get(schema3);
  }
  has(schema3) {
    return this._map.has(schema3);
  }
};
function registry() {
  return new $ZodRegistry();
}
__name(registry, "registry");
var globalRegistry = /* @__PURE__ */ registry();

// node_modules/zod/v4/core/api.js
function _string(Class3, params) {
  return new Class3({
    type: "string",
    ...normalizeParams2(params)
  });
}
__name(_string, "_string");
function _coercedString(Class3, params) {
  return new Class3({
    type: "string",
    coerce: true,
    ...normalizeParams2(params)
  });
}
__name(_coercedString, "_coercedString");
function _email(Class3, params) {
  return new Class3({
    type: "string",
    format: "email",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_email, "_email");
function _guid(Class3, params) {
  return new Class3({
    type: "string",
    format: "guid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_guid, "_guid");
function _uuid(Class3, params) {
  return new Class3({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_uuid, "_uuid");
function _uuidv4(Class3, params) {
  return new Class3({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v4",
    ...normalizeParams2(params)
  });
}
__name(_uuidv4, "_uuidv4");
function _uuidv6(Class3, params) {
  return new Class3({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v6",
    ...normalizeParams2(params)
  });
}
__name(_uuidv6, "_uuidv6");
function _uuidv7(Class3, params) {
  return new Class3({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v7",
    ...normalizeParams2(params)
  });
}
__name(_uuidv7, "_uuidv7");
function _url(Class3, params) {
  return new Class3({
    type: "string",
    format: "url",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_url, "_url");
function _emoji2(Class3, params) {
  return new Class3({
    type: "string",
    format: "emoji",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_emoji2, "_emoji");
function _nanoid(Class3, params) {
  return new Class3({
    type: "string",
    format: "nanoid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_nanoid, "_nanoid");
function _cuid(Class3, params) {
  return new Class3({
    type: "string",
    format: "cuid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_cuid, "_cuid");
function _cuid2(Class3, params) {
  return new Class3({
    type: "string",
    format: "cuid2",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_cuid2, "_cuid2");
function _ulid(Class3, params) {
  return new Class3({
    type: "string",
    format: "ulid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_ulid, "_ulid");
function _xid(Class3, params) {
  return new Class3({
    type: "string",
    format: "xid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_xid, "_xid");
function _ksuid(Class3, params) {
  return new Class3({
    type: "string",
    format: "ksuid",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_ksuid, "_ksuid");
function _ipv4(Class3, params) {
  return new Class3({
    type: "string",
    format: "ipv4",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_ipv4, "_ipv4");
function _ipv6(Class3, params) {
  return new Class3({
    type: "string",
    format: "ipv6",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_ipv6, "_ipv6");
function _cidrv4(Class3, params) {
  return new Class3({
    type: "string",
    format: "cidrv4",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_cidrv4, "_cidrv4");
function _cidrv6(Class3, params) {
  return new Class3({
    type: "string",
    format: "cidrv6",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_cidrv6, "_cidrv6");
function _base64(Class3, params) {
  return new Class3({
    type: "string",
    format: "base64",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_base64, "_base64");
function _base64url(Class3, params) {
  return new Class3({
    type: "string",
    format: "base64url",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_base64url, "_base64url");
function _e164(Class3, params) {
  return new Class3({
    type: "string",
    format: "e164",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_e164, "_e164");
function _jwt(Class3, params) {
  return new Class3({
    type: "string",
    format: "jwt",
    check: "string_format",
    abort: false,
    ...normalizeParams2(params)
  });
}
__name(_jwt, "_jwt");
function _isoDateTime(Class3, params) {
  return new Class3({
    type: "string",
    format: "datetime",
    check: "string_format",
    offset: false,
    local: false,
    precision: null,
    ...normalizeParams2(params)
  });
}
__name(_isoDateTime, "_isoDateTime");
function _isoDate(Class3, params) {
  return new Class3({
    type: "string",
    format: "date",
    check: "string_format",
    ...normalizeParams2(params)
  });
}
__name(_isoDate, "_isoDate");
function _isoTime(Class3, params) {
  return new Class3({
    type: "string",
    format: "time",
    check: "string_format",
    precision: null,
    ...normalizeParams2(params)
  });
}
__name(_isoTime, "_isoTime");
function _isoDuration(Class3, params) {
  return new Class3({
    type: "string",
    format: "duration",
    check: "string_format",
    ...normalizeParams2(params)
  });
}
__name(_isoDuration, "_isoDuration");
function _number(Class3, params) {
  return new Class3({
    type: "number",
    checks: [],
    ...normalizeParams2(params)
  });
}
__name(_number, "_number");
function _coercedNumber(Class3, params) {
  return new Class3({
    type: "number",
    coerce: true,
    checks: [],
    ...normalizeParams2(params)
  });
}
__name(_coercedNumber, "_coercedNumber");
function _int(Class3, params) {
  return new Class3({
    type: "number",
    check: "number_format",
    abort: false,
    format: "safeint",
    ...normalizeParams2(params)
  });
}
__name(_int, "_int");
function _boolean(Class3, params) {
  return new Class3({
    type: "boolean",
    ...normalizeParams2(params)
  });
}
__name(_boolean, "_boolean");
function _coercedBoolean(Class3, params) {
  return new Class3({
    type: "boolean",
    coerce: true,
    ...normalizeParams2(params)
  });
}
__name(_coercedBoolean, "_coercedBoolean");
function _coercedBigint(Class3, params) {
  return new Class3({
    type: "bigint",
    coerce: true,
    ...normalizeParams2(params)
  });
}
__name(_coercedBigint, "_coercedBigint");
function _unknown(Class3) {
  return new Class3({
    type: "unknown"
  });
}
__name(_unknown, "_unknown");
function _never(Class3, params) {
  return new Class3({
    type: "never",
    ...normalizeParams2(params)
  });
}
__name(_never, "_never");
function _date(Class3, params) {
  return new Class3({
    type: "date",
    ...normalizeParams2(params)
  });
}
__name(_date, "_date");
function _coercedDate(Class3, params) {
  return new Class3({
    type: "date",
    coerce: true,
    ...normalizeParams2(params)
  });
}
__name(_coercedDate, "_coercedDate");
function _lt(value, params) {
  return new $ZodCheckLessThan({
    check: "less_than",
    ...normalizeParams2(params),
    value,
    inclusive: false
  });
}
__name(_lt, "_lt");
function _lte(value, params) {
  return new $ZodCheckLessThan({
    check: "less_than",
    ...normalizeParams2(params),
    value,
    inclusive: true
  });
}
__name(_lte, "_lte");
function _gt(value, params) {
  return new $ZodCheckGreaterThan({
    check: "greater_than",
    ...normalizeParams2(params),
    value,
    inclusive: false
  });
}
__name(_gt, "_gt");
function _gte(value, params) {
  return new $ZodCheckGreaterThan({
    check: "greater_than",
    ...normalizeParams2(params),
    value,
    inclusive: true
  });
}
__name(_gte, "_gte");
function _multipleOf(value, params) {
  return new $ZodCheckMultipleOf({
    check: "multiple_of",
    ...normalizeParams2(params),
    value
  });
}
__name(_multipleOf, "_multipleOf");
function _maxLength(maximum, params) {
  const ch = new $ZodCheckMaxLength({
    check: "max_length",
    ...normalizeParams2(params),
    maximum
  });
  return ch;
}
__name(_maxLength, "_maxLength");
function _minLength(minimum, params) {
  return new $ZodCheckMinLength({
    check: "min_length",
    ...normalizeParams2(params),
    minimum
  });
}
__name(_minLength, "_minLength");
function _length(length, params) {
  return new $ZodCheckLengthEquals({
    check: "length_equals",
    ...normalizeParams2(params),
    length
  });
}
__name(_length, "_length");
function _regex(pattern, params) {
  return new $ZodCheckRegex({
    check: "string_format",
    format: "regex",
    ...normalizeParams2(params),
    pattern
  });
}
__name(_regex, "_regex");
function _lowercase(params) {
  return new $ZodCheckLowerCase({
    check: "string_format",
    format: "lowercase",
    ...normalizeParams2(params)
  });
}
__name(_lowercase, "_lowercase");
function _uppercase(params) {
  return new $ZodCheckUpperCase({
    check: "string_format",
    format: "uppercase",
    ...normalizeParams2(params)
  });
}
__name(_uppercase, "_uppercase");
function _includes(includes, params) {
  return new $ZodCheckIncludes({
    check: "string_format",
    format: "includes",
    ...normalizeParams2(params),
    includes
  });
}
__name(_includes, "_includes");
function _startsWith(prefix, params) {
  return new $ZodCheckStartsWith({
    check: "string_format",
    format: "starts_with",
    ...normalizeParams2(params),
    prefix
  });
}
__name(_startsWith, "_startsWith");
function _endsWith(suffix, params) {
  return new $ZodCheckEndsWith({
    check: "string_format",
    format: "ends_with",
    ...normalizeParams2(params),
    suffix
  });
}
__name(_endsWith, "_endsWith");
function _overwrite(tx) {
  return new $ZodCheckOverwrite({
    check: "overwrite",
    tx
  });
}
__name(_overwrite, "_overwrite");
function _normalize(form) {
  return _overwrite((input) => input.normalize(form));
}
__name(_normalize, "_normalize");
function _trim() {
  return _overwrite((input) => input.trim());
}
__name(_trim, "_trim");
function _toLowerCase() {
  return _overwrite((input) => input.toLowerCase());
}
__name(_toLowerCase, "_toLowerCase");
function _toUpperCase() {
  return _overwrite((input) => input.toUpperCase());
}
__name(_toUpperCase, "_toUpperCase");
function _array(Class3, element, params) {
  return new Class3({
    type: "array",
    element,
    // get element() {
    //   return element;
    // },
    ...normalizeParams2(params)
  });
}
__name(_array, "_array");
function _custom(Class3, fn, _params) {
  const norm = normalizeParams2(_params);
  norm.abort ?? (norm.abort = true);
  const schema3 = new Class3({
    type: "custom",
    check: "custom",
    fn,
    ...norm
  });
  return schema3;
}
__name(_custom, "_custom");
function _refine(Class3, fn, _params) {
  const schema3 = new Class3({
    type: "custom",
    check: "custom",
    fn,
    ...normalizeParams2(_params)
  });
  return schema3;
}
__name(_refine, "_refine");
function _superRefine(fn) {
  const ch = _check((payload) => {
    payload.addIssue = (issue3) => {
      if (typeof issue3 === "string") {
        payload.issues.push(issue2(issue3, payload.value, ch._zod.def));
      } else {
        const _issue = issue3;
        if (_issue.fatal) _issue.continue = false;
        _issue.code ?? (_issue.code = "custom");
        _issue.input ?? (_issue.input = payload.value);
        _issue.inst ?? (_issue.inst = ch);
        _issue.continue ?? (_issue.continue = !ch._zod.def.abort);
        payload.issues.push(issue2(_issue));
      }
    };
    return fn(payload.value, payload);
  });
  return ch;
}
__name(_superRefine, "_superRefine");
function _check(fn, params) {
  const ch = new $ZodCheck({
    check: "custom",
    ...normalizeParams2(params)
  });
  ch._zod.check = fn;
  return ch;
}
__name(_check, "_check");

// node_modules/zod/v4/classic/iso.js
var ZodISODateTime = /* @__PURE__ */ $constructor("ZodISODateTime", (inst, def) => {
  $ZodISODateTime.init(inst, def);
  ZodStringFormat.init(inst, def);
});
function datetime2(params) {
  return _isoDateTime(ZodISODateTime, params);
}
__name(datetime2, "datetime");
var ZodISODate = /* @__PURE__ */ $constructor("ZodISODate", (inst, def) => {
  $ZodISODate.init(inst, def);
  ZodStringFormat.init(inst, def);
});
function date2(params) {
  return _isoDate(ZodISODate, params);
}
__name(date2, "date");
var ZodISOTime = /* @__PURE__ */ $constructor("ZodISOTime", (inst, def) => {
  $ZodISOTime.init(inst, def);
  ZodStringFormat.init(inst, def);
});
function time2(params) {
  return _isoTime(ZodISOTime, params);
}
__name(time2, "time");
var ZodISODuration = /* @__PURE__ */ $constructor("ZodISODuration", (inst, def) => {
  $ZodISODuration.init(inst, def);
  ZodStringFormat.init(inst, def);
});
function duration2(params) {
  return _isoDuration(ZodISODuration, params);
}
__name(duration2, "duration");

// node_modules/zod/v4/classic/errors.js
var initializer2 = /* @__PURE__ */ __name((inst, issues) => {
  $ZodError.init(inst, issues);
  inst.name = "ZodError";
  Object.defineProperties(inst, {
    format: {
      value: /* @__PURE__ */ __name((mapper) => formatError(inst, mapper), "value")
    },
    flatten: {
      value: /* @__PURE__ */ __name((mapper) => flattenError(inst, mapper), "value")
    },
    addIssue: {
      value: /* @__PURE__ */ __name((issue3) => {
        inst.issues.push(issue3);
        inst.message = JSON.stringify(inst.issues, jsonStringifyReplacer2, 2);
      }, "value")
    },
    addIssues: {
      value: /* @__PURE__ */ __name((issues2) => {
        inst.issues.push(...issues2);
        inst.message = JSON.stringify(inst.issues, jsonStringifyReplacer2, 2);
      }, "value")
    },
    isEmpty: {
      get() {
        return inst.issues.length === 0;
      }
    }
  });
}, "initializer");
var ZodError = $constructor("ZodError", initializer2);
var ZodRealError = $constructor("ZodError", initializer2, {
  Parent: Error
});

// node_modules/zod/v4/classic/parse.js
var parse2 = /* @__PURE__ */ _parse(ZodRealError);
var parseAsync2 = /* @__PURE__ */ _parseAsync(ZodRealError);
var safeParse2 = /* @__PURE__ */ _safeParse(ZodRealError);
var safeParseAsync2 = /* @__PURE__ */ _safeParseAsync(ZodRealError);
var encode = /* @__PURE__ */ _encode(ZodRealError);
var decode = /* @__PURE__ */ _decode(ZodRealError);
var encodeAsync = /* @__PURE__ */ _encodeAsync(ZodRealError);
var decodeAsync = /* @__PURE__ */ _decodeAsync(ZodRealError);
var safeEncode = /* @__PURE__ */ _safeEncode(ZodRealError);
var safeDecode = /* @__PURE__ */ _safeDecode(ZodRealError);
var safeEncodeAsync = /* @__PURE__ */ _safeEncodeAsync(ZodRealError);
var safeDecodeAsync = /* @__PURE__ */ _safeDecodeAsync(ZodRealError);

// node_modules/zod/v4/classic/schemas.js
var ZodType = /* @__PURE__ */ $constructor("ZodType", (inst, def) => {
  $ZodType.init(inst, def);
  inst.def = def;
  inst.type = def.type;
  Object.defineProperty(inst, "_def", {
    value: def
  });
  inst.check = (...checks) => {
    return inst.clone(util_exports2.mergeDefs(def, {
      checks: [
        ...def.checks ?? [],
        ...checks.map((ch) => typeof ch === "function" ? {
          _zod: {
            check: ch,
            def: {
              check: "custom"
            },
            onattach: []
          }
        } : ch)
      ]
    }));
  };
  inst.clone = (def2, params) => clone2(inst, def2, params);
  inst.brand = () => inst;
  inst.register = (reg, meta) => {
    reg.add(inst, meta);
    return inst;
  };
  inst.parse = (data, params) => parse2(inst, data, params, {
    callee: inst.parse
  });
  inst.safeParse = (data, params) => safeParse2(inst, data, params);
  inst.parseAsync = async (data, params) => parseAsync2(inst, data, params, {
    callee: inst.parseAsync
  });
  inst.safeParseAsync = async (data, params) => safeParseAsync2(inst, data, params);
  inst.spa = inst.safeParseAsync;
  inst.encode = (data, params) => encode(inst, data, params);
  inst.decode = (data, params) => decode(inst, data, params);
  inst.encodeAsync = async (data, params) => encodeAsync(inst, data, params);
  inst.decodeAsync = async (data, params) => decodeAsync(inst, data, params);
  inst.safeEncode = (data, params) => safeEncode(inst, data, params);
  inst.safeDecode = (data, params) => safeDecode(inst, data, params);
  inst.safeEncodeAsync = async (data, params) => safeEncodeAsync(inst, data, params);
  inst.safeDecodeAsync = async (data, params) => safeDecodeAsync(inst, data, params);
  inst.refine = (check, params) => inst.check(refine(check, params));
  inst.superRefine = (refinement) => inst.check(superRefine(refinement));
  inst.overwrite = (fn) => inst.check(_overwrite(fn));
  inst.optional = () => optional(inst);
  inst.nullable = () => nullable(inst);
  inst.nullish = () => optional(nullable(inst));
  inst.nonoptional = (params) => nonoptional(inst, params);
  inst.array = () => array(inst);
  inst.or = (arg) => union([
    inst,
    arg
  ]);
  inst.and = (arg) => intersection(inst, arg);
  inst.transform = (tx) => pipe(inst, transform(tx));
  inst.default = (def2) => _default(inst, def2);
  inst.prefault = (def2) => prefault(inst, def2);
  inst.catch = (params) => _catch(inst, params);
  inst.pipe = (target) => pipe(inst, target);
  inst.readonly = () => readonly(inst);
  inst.describe = (description) => {
    const cl = inst.clone();
    globalRegistry.add(cl, {
      description
    });
    return cl;
  };
  Object.defineProperty(inst, "description", {
    get() {
      return globalRegistry.get(inst)?.description;
    },
    configurable: true
  });
  inst.meta = (...args) => {
    if (args.length === 0) {
      return globalRegistry.get(inst);
    }
    const cl = inst.clone();
    globalRegistry.add(cl, args[0]);
    return cl;
  };
  inst.isOptional = () => inst.safeParse(void 0).success;
  inst.isNullable = () => inst.safeParse(null).success;
  return inst;
});
var _ZodString = /* @__PURE__ */ $constructor("_ZodString", (inst, def) => {
  $ZodString.init(inst, def);
  ZodType.init(inst, def);
  const bag = inst._zod.bag;
  inst.format = bag.format ?? null;
  inst.minLength = bag.minimum ?? null;
  inst.maxLength = bag.maximum ?? null;
  inst.regex = (...args) => inst.check(_regex(...args));
  inst.includes = (...args) => inst.check(_includes(...args));
  inst.startsWith = (...args) => inst.check(_startsWith(...args));
  inst.endsWith = (...args) => inst.check(_endsWith(...args));
  inst.min = (...args) => inst.check(_minLength(...args));
  inst.max = (...args) => inst.check(_maxLength(...args));
  inst.length = (...args) => inst.check(_length(...args));
  inst.nonempty = (...args) => inst.check(_minLength(1, ...args));
  inst.lowercase = (params) => inst.check(_lowercase(params));
  inst.uppercase = (params) => inst.check(_uppercase(params));
  inst.trim = () => inst.check(_trim());
  inst.normalize = (...args) => inst.check(_normalize(...args));
  inst.toLowerCase = () => inst.check(_toLowerCase());
  inst.toUpperCase = () => inst.check(_toUpperCase());
});
var ZodString = /* @__PURE__ */ $constructor("ZodString", (inst, def) => {
  $ZodString.init(inst, def);
  _ZodString.init(inst, def);
  inst.email = (params) => inst.check(_email(ZodEmail, params));
  inst.url = (params) => inst.check(_url(ZodURL, params));
  inst.jwt = (params) => inst.check(_jwt(ZodJWT, params));
  inst.emoji = (params) => inst.check(_emoji2(ZodEmoji, params));
  inst.guid = (params) => inst.check(_guid(ZodGUID, params));
  inst.uuid = (params) => inst.check(_uuid(ZodUUID, params));
  inst.uuidv4 = (params) => inst.check(_uuidv4(ZodUUID, params));
  inst.uuidv6 = (params) => inst.check(_uuidv6(ZodUUID, params));
  inst.uuidv7 = (params) => inst.check(_uuidv7(ZodUUID, params));
  inst.nanoid = (params) => inst.check(_nanoid(ZodNanoID, params));
  inst.guid = (params) => inst.check(_guid(ZodGUID, params));
  inst.cuid = (params) => inst.check(_cuid(ZodCUID, params));
  inst.cuid2 = (params) => inst.check(_cuid2(ZodCUID2, params));
  inst.ulid = (params) => inst.check(_ulid(ZodULID, params));
  inst.base64 = (params) => inst.check(_base64(ZodBase64, params));
  inst.base64url = (params) => inst.check(_base64url(ZodBase64URL, params));
  inst.xid = (params) => inst.check(_xid(ZodXID, params));
  inst.ksuid = (params) => inst.check(_ksuid(ZodKSUID, params));
  inst.ipv4 = (params) => inst.check(_ipv4(ZodIPv4, params));
  inst.ipv6 = (params) => inst.check(_ipv6(ZodIPv6, params));
  inst.cidrv4 = (params) => inst.check(_cidrv4(ZodCIDRv4, params));
  inst.cidrv6 = (params) => inst.check(_cidrv6(ZodCIDRv6, params));
  inst.e164 = (params) => inst.check(_e164(ZodE164, params));
  inst.datetime = (params) => inst.check(datetime2(params));
  inst.date = (params) => inst.check(date2(params));
  inst.time = (params) => inst.check(time2(params));
  inst.duration = (params) => inst.check(duration2(params));
});
function string2(params) {
  return _string(ZodString, params);
}
__name(string2, "string");
var ZodStringFormat = /* @__PURE__ */ $constructor("ZodStringFormat", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  _ZodString.init(inst, def);
});
var ZodEmail = /* @__PURE__ */ $constructor("ZodEmail", (inst, def) => {
  $ZodEmail.init(inst, def);
  ZodStringFormat.init(inst, def);
});
function email2(params) {
  return _email(ZodEmail, params);
}
__name(email2, "email");
var ZodGUID = /* @__PURE__ */ $constructor("ZodGUID", (inst, def) => {
  $ZodGUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodUUID = /* @__PURE__ */ $constructor("ZodUUID", (inst, def) => {
  $ZodUUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodURL = /* @__PURE__ */ $constructor("ZodURL", (inst, def) => {
  $ZodURL.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodEmoji = /* @__PURE__ */ $constructor("ZodEmoji", (inst, def) => {
  $ZodEmoji.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodNanoID = /* @__PURE__ */ $constructor("ZodNanoID", (inst, def) => {
  $ZodNanoID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCUID = /* @__PURE__ */ $constructor("ZodCUID", (inst, def) => {
  $ZodCUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCUID2 = /* @__PURE__ */ $constructor("ZodCUID2", (inst, def) => {
  $ZodCUID2.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodULID = /* @__PURE__ */ $constructor("ZodULID", (inst, def) => {
  $ZodULID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodXID = /* @__PURE__ */ $constructor("ZodXID", (inst, def) => {
  $ZodXID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodKSUID = /* @__PURE__ */ $constructor("ZodKSUID", (inst, def) => {
  $ZodKSUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodIPv4 = /* @__PURE__ */ $constructor("ZodIPv4", (inst, def) => {
  $ZodIPv4.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodIPv6 = /* @__PURE__ */ $constructor("ZodIPv6", (inst, def) => {
  $ZodIPv6.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCIDRv4 = /* @__PURE__ */ $constructor("ZodCIDRv4", (inst, def) => {
  $ZodCIDRv4.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCIDRv6 = /* @__PURE__ */ $constructor("ZodCIDRv6", (inst, def) => {
  $ZodCIDRv6.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodBase64 = /* @__PURE__ */ $constructor("ZodBase64", (inst, def) => {
  $ZodBase64.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodBase64URL = /* @__PURE__ */ $constructor("ZodBase64URL", (inst, def) => {
  $ZodBase64URL.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodE164 = /* @__PURE__ */ $constructor("ZodE164", (inst, def) => {
  $ZodE164.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodJWT = /* @__PURE__ */ $constructor("ZodJWT", (inst, def) => {
  $ZodJWT.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodNumber = /* @__PURE__ */ $constructor("ZodNumber", (inst, def) => {
  $ZodNumber.init(inst, def);
  ZodType.init(inst, def);
  inst.gt = (value, params) => inst.check(_gt(value, params));
  inst.gte = (value, params) => inst.check(_gte(value, params));
  inst.min = (value, params) => inst.check(_gte(value, params));
  inst.lt = (value, params) => inst.check(_lt(value, params));
  inst.lte = (value, params) => inst.check(_lte(value, params));
  inst.max = (value, params) => inst.check(_lte(value, params));
  inst.int = (params) => inst.check(int(params));
  inst.safe = (params) => inst.check(int(params));
  inst.positive = (params) => inst.check(_gt(0, params));
  inst.nonnegative = (params) => inst.check(_gte(0, params));
  inst.negative = (params) => inst.check(_lt(0, params));
  inst.nonpositive = (params) => inst.check(_lte(0, params));
  inst.multipleOf = (value, params) => inst.check(_multipleOf(value, params));
  inst.step = (value, params) => inst.check(_multipleOf(value, params));
  inst.finite = () => inst;
  const bag = inst._zod.bag;
  inst.minValue = Math.max(bag.minimum ?? Number.NEGATIVE_INFINITY, bag.exclusiveMinimum ?? Number.NEGATIVE_INFINITY) ?? null;
  inst.maxValue = Math.min(bag.maximum ?? Number.POSITIVE_INFINITY, bag.exclusiveMaximum ?? Number.POSITIVE_INFINITY) ?? null;
  inst.isInt = (bag.format ?? "").includes("int") || Number.isSafeInteger(bag.multipleOf ?? 0.5);
  inst.isFinite = true;
  inst.format = bag.format ?? null;
});
function number2(params) {
  return _number(ZodNumber, params);
}
__name(number2, "number");
var ZodNumberFormat = /* @__PURE__ */ $constructor("ZodNumberFormat", (inst, def) => {
  $ZodNumberFormat.init(inst, def);
  ZodNumber.init(inst, def);
});
function int(params) {
  return _int(ZodNumberFormat, params);
}
__name(int, "int");
var ZodBoolean = /* @__PURE__ */ $constructor("ZodBoolean", (inst, def) => {
  $ZodBoolean.init(inst, def);
  ZodType.init(inst, def);
});
function boolean2(params) {
  return _boolean(ZodBoolean, params);
}
__name(boolean2, "boolean");
var ZodBigInt = /* @__PURE__ */ $constructor("ZodBigInt", (inst, def) => {
  $ZodBigInt.init(inst, def);
  ZodType.init(inst, def);
  inst.gte = (value, params) => inst.check(_gte(value, params));
  inst.min = (value, params) => inst.check(_gte(value, params));
  inst.gt = (value, params) => inst.check(_gt(value, params));
  inst.gte = (value, params) => inst.check(_gte(value, params));
  inst.min = (value, params) => inst.check(_gte(value, params));
  inst.lt = (value, params) => inst.check(_lt(value, params));
  inst.lte = (value, params) => inst.check(_lte(value, params));
  inst.max = (value, params) => inst.check(_lte(value, params));
  inst.positive = (params) => inst.check(_gt(BigInt(0), params));
  inst.negative = (params) => inst.check(_lt(BigInt(0), params));
  inst.nonpositive = (params) => inst.check(_lte(BigInt(0), params));
  inst.nonnegative = (params) => inst.check(_gte(BigInt(0), params));
  inst.multipleOf = (value, params) => inst.check(_multipleOf(value, params));
  const bag = inst._zod.bag;
  inst.minValue = bag.minimum ?? null;
  inst.maxValue = bag.maximum ?? null;
  inst.format = bag.format ?? null;
});
var ZodUnknown = /* @__PURE__ */ $constructor("ZodUnknown", (inst, def) => {
  $ZodUnknown.init(inst, def);
  ZodType.init(inst, def);
});
function unknown() {
  return _unknown(ZodUnknown);
}
__name(unknown, "unknown");
var ZodNever = /* @__PURE__ */ $constructor("ZodNever", (inst, def) => {
  $ZodNever.init(inst, def);
  ZodType.init(inst, def);
});
function never(params) {
  return _never(ZodNever, params);
}
__name(never, "never");
var ZodDate = /* @__PURE__ */ $constructor("ZodDate", (inst, def) => {
  $ZodDate.init(inst, def);
  ZodType.init(inst, def);
  inst.min = (value, params) => inst.check(_gte(value, params));
  inst.max = (value, params) => inst.check(_lte(value, params));
  const c = inst._zod.bag;
  inst.minDate = c.minimum ? new Date(c.minimum) : null;
  inst.maxDate = c.maximum ? new Date(c.maximum) : null;
});
function date3(params) {
  return _date(ZodDate, params);
}
__name(date3, "date");
var ZodArray = /* @__PURE__ */ $constructor("ZodArray", (inst, def) => {
  $ZodArray.init(inst, def);
  ZodType.init(inst, def);
  inst.element = def.element;
  inst.min = (minLength, params) => inst.check(_minLength(minLength, params));
  inst.nonempty = (params) => inst.check(_minLength(1, params));
  inst.max = (maxLength, params) => inst.check(_maxLength(maxLength, params));
  inst.length = (len, params) => inst.check(_length(len, params));
  inst.unwrap = () => inst.element;
});
function array(element, params) {
  return _array(ZodArray, element, params);
}
__name(array, "array");
var ZodObject = /* @__PURE__ */ $constructor("ZodObject", (inst, def) => {
  $ZodObjectJIT.init(inst, def);
  ZodType.init(inst, def);
  util_exports2.defineLazy(inst, "shape", () => {
    return def.shape;
  });
  inst.keyof = () => _enum(Object.keys(inst._zod.def.shape));
  inst.catchall = (catchall) => inst.clone({
    ...inst._zod.def,
    catchall
  });
  inst.passthrough = () => inst.clone({
    ...inst._zod.def,
    catchall: unknown()
  });
  inst.loose = () => inst.clone({
    ...inst._zod.def,
    catchall: unknown()
  });
  inst.strict = () => inst.clone({
    ...inst._zod.def,
    catchall: never()
  });
  inst.strip = () => inst.clone({
    ...inst._zod.def,
    catchall: void 0
  });
  inst.extend = (incoming) => {
    return util_exports2.extend(inst, incoming);
  };
  inst.safeExtend = (incoming) => {
    return util_exports2.safeExtend(inst, incoming);
  };
  inst.merge = (other) => util_exports2.merge(inst, other);
  inst.pick = (mask) => util_exports2.pick(inst, mask);
  inst.omit = (mask) => util_exports2.omit(inst, mask);
  inst.partial = (...args) => util_exports2.partial(ZodOptional, inst, args[0]);
  inst.required = (...args) => util_exports2.required(ZodNonOptional, inst, args[0]);
});
function object(shape, params) {
  const def = {
    type: "object",
    shape: shape ?? {},
    ...util_exports2.normalizeParams(params)
  };
  return new ZodObject(def);
}
__name(object, "object");
var ZodUnion = /* @__PURE__ */ $constructor("ZodUnion", (inst, def) => {
  $ZodUnion.init(inst, def);
  ZodType.init(inst, def);
  inst.options = def.options;
});
function union(options, params) {
  return new ZodUnion({
    type: "union",
    options,
    ...util_exports2.normalizeParams(params)
  });
}
__name(union, "union");
var ZodIntersection = /* @__PURE__ */ $constructor("ZodIntersection", (inst, def) => {
  $ZodIntersection.init(inst, def);
  ZodType.init(inst, def);
});
function intersection(left, right) {
  return new ZodIntersection({
    type: "intersection",
    left,
    right
  });
}
__name(intersection, "intersection");
var ZodRecord = /* @__PURE__ */ $constructor("ZodRecord", (inst, def) => {
  $ZodRecord.init(inst, def);
  ZodType.init(inst, def);
  inst.keyType = def.keyType;
  inst.valueType = def.valueType;
});
function record(keyType, valueType, params) {
  return new ZodRecord({
    type: "record",
    keyType,
    valueType,
    ...util_exports2.normalizeParams(params)
  });
}
__name(record, "record");
var ZodEnum = /* @__PURE__ */ $constructor("ZodEnum", (inst, def) => {
  $ZodEnum.init(inst, def);
  ZodType.init(inst, def);
  inst.enum = def.entries;
  inst.options = Object.values(def.entries);
  const keys = new Set(Object.keys(def.entries));
  inst.extract = (values, params) => {
    const newEntries = {};
    for (const value of values) {
      if (keys.has(value)) {
        newEntries[value] = def.entries[value];
      } else throw new Error(`Key ${value} not found in enum`);
    }
    return new ZodEnum({
      ...def,
      checks: [],
      ...util_exports2.normalizeParams(params),
      entries: newEntries
    });
  };
  inst.exclude = (values, params) => {
    const newEntries = {
      ...def.entries
    };
    for (const value of values) {
      if (keys.has(value)) {
        delete newEntries[value];
      } else throw new Error(`Key ${value} not found in enum`);
    }
    return new ZodEnum({
      ...def,
      checks: [],
      ...util_exports2.normalizeParams(params),
      entries: newEntries
    });
  };
});
function _enum(values, params) {
  const entries = Array.isArray(values) ? Object.fromEntries(values.map((v) => [
    v,
    v
  ])) : values;
  return new ZodEnum({
    type: "enum",
    entries,
    ...util_exports2.normalizeParams(params)
  });
}
__name(_enum, "_enum");
var ZodTransform = /* @__PURE__ */ $constructor("ZodTransform", (inst, def) => {
  $ZodTransform.init(inst, def);
  ZodType.init(inst, def);
  inst._zod.parse = (payload, _ctx) => {
    if (_ctx.direction === "backward") {
      throw new $ZodEncodeError(inst.constructor.name);
    }
    payload.addIssue = (issue3) => {
      if (typeof issue3 === "string") {
        payload.issues.push(util_exports2.issue(issue3, payload.value, def));
      } else {
        const _issue = issue3;
        if (_issue.fatal) _issue.continue = false;
        _issue.code ?? (_issue.code = "custom");
        _issue.input ?? (_issue.input = payload.value);
        _issue.inst ?? (_issue.inst = inst);
        payload.issues.push(util_exports2.issue(_issue));
      }
    };
    const output = def.transform(payload.value, payload);
    if (output instanceof Promise) {
      return output.then((output2) => {
        payload.value = output2;
        return payload;
      });
    }
    payload.value = output;
    return payload;
  };
});
function transform(fn) {
  return new ZodTransform({
    type: "transform",
    transform: fn
  });
}
__name(transform, "transform");
var ZodOptional = /* @__PURE__ */ $constructor("ZodOptional", (inst, def) => {
  $ZodOptional.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
});
function optional(innerType) {
  return new ZodOptional({
    type: "optional",
    innerType
  });
}
__name(optional, "optional");
var ZodNullable = /* @__PURE__ */ $constructor("ZodNullable", (inst, def) => {
  $ZodNullable.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
});
function nullable(innerType) {
  return new ZodNullable({
    type: "nullable",
    innerType
  });
}
__name(nullable, "nullable");
var ZodDefault = /* @__PURE__ */ $constructor("ZodDefault", (inst, def) => {
  $ZodDefault.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
  inst.removeDefault = inst.unwrap;
});
function _default(innerType, defaultValue) {
  return new ZodDefault({
    type: "default",
    innerType,
    get defaultValue() {
      return typeof defaultValue === "function" ? defaultValue() : util_exports2.shallowClone(defaultValue);
    }
  });
}
__name(_default, "_default");
var ZodPrefault = /* @__PURE__ */ $constructor("ZodPrefault", (inst, def) => {
  $ZodPrefault.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
});
function prefault(innerType, defaultValue) {
  return new ZodPrefault({
    type: "prefault",
    innerType,
    get defaultValue() {
      return typeof defaultValue === "function" ? defaultValue() : util_exports2.shallowClone(defaultValue);
    }
  });
}
__name(prefault, "prefault");
var ZodNonOptional = /* @__PURE__ */ $constructor("ZodNonOptional", (inst, def) => {
  $ZodNonOptional.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
});
function nonoptional(innerType, params) {
  return new ZodNonOptional({
    type: "nonoptional",
    innerType,
    ...util_exports2.normalizeParams(params)
  });
}
__name(nonoptional, "nonoptional");
var ZodCatch = /* @__PURE__ */ $constructor("ZodCatch", (inst, def) => {
  $ZodCatch.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
  inst.removeCatch = inst.unwrap;
});
function _catch(innerType, catchValue) {
  return new ZodCatch({
    type: "catch",
    innerType,
    catchValue: typeof catchValue === "function" ? catchValue : () => catchValue
  });
}
__name(_catch, "_catch");
var ZodPipe = /* @__PURE__ */ $constructor("ZodPipe", (inst, def) => {
  $ZodPipe.init(inst, def);
  ZodType.init(inst, def);
  inst.in = def.in;
  inst.out = def.out;
});
function pipe(in_, out) {
  return new ZodPipe({
    type: "pipe",
    in: in_,
    out
  });
}
__name(pipe, "pipe");
var ZodReadonly = /* @__PURE__ */ $constructor("ZodReadonly", (inst, def) => {
  $ZodReadonly.init(inst, def);
  ZodType.init(inst, def);
  inst.unwrap = () => inst._zod.def.innerType;
});
function readonly(innerType) {
  return new ZodReadonly({
    type: "readonly",
    innerType
  });
}
__name(readonly, "readonly");
var ZodCustom = /* @__PURE__ */ $constructor("ZodCustom", (inst, def) => {
  $ZodCustom.init(inst, def);
  ZodType.init(inst, def);
});
function custom(fn, _params) {
  return _custom(ZodCustom, fn ?? (() => true), _params);
}
__name(custom, "custom");
function refine(fn, _params = {}) {
  return _refine(ZodCustom, fn, _params);
}
__name(refine, "refine");
function superRefine(fn) {
  return _superRefine(fn);
}
__name(superRefine, "superRefine");

// node_modules/zod/v4/classic/compat.js
var ZodFirstPartyTypeKind;
/* @__PURE__ */ (function(ZodFirstPartyTypeKind2) {
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));

// node_modules/zod/v4/classic/coerce.js
var coerce_exports = {};
__export(coerce_exports, {
  bigint: () => bigint2,
  boolean: () => boolean3,
  date: () => date4,
  number: () => number3,
  string: () => string3
});
function string3(params) {
  return _coercedString(ZodString, params);
}
__name(string3, "string");
function number3(params) {
  return _coercedNumber(ZodNumber, params);
}
__name(number3, "number");
function boolean3(params) {
  return _coercedBoolean(ZodBoolean, params);
}
__name(boolean3, "boolean");
function bigint2(params) {
  return _coercedBigint(ZodBigInt, params);
}
__name(bigint2, "bigint");
function date4(params) {
  return _coercedDate(ZodDate, params);
}
__name(date4, "date");

// node_modules/zod/v4/classic/external.js
config(en_default());

// node_modules/better-auth/dist/shared/better-auth.CW6D9eSx.mjs
var getDate = /* @__PURE__ */ __name((span, unit = "ms") => {
  return new Date(Date.now() + (unit === "sec" ? span * 1e3 : span));
}, "getDate");

// node_modules/better-auth/dist/shared/better-auth.DdzSJf-n.mjs
var BetterAuthError = class extends Error {
  static {
    __name(this, "BetterAuthError");
  }
  constructor(message2, cause) {
    super(message2);
    this.name = "BetterAuthError";
    this.message = message2;
    this.cause = cause;
    this.stack = "";
  }
};

// node_modules/better-auth/dist/shared/better-auth.CiuwFiHM.mjs
var _envShim = /* @__PURE__ */ Object.create(null);
var _getEnv = /* @__PURE__ */ __name((useShim) => globalThis.process?.env || //@ts-expect-error
globalThis.Deno?.env.toObject() || //@ts-expect-error
globalThis.__env__ || (useShim ? _envShim : globalThis), "_getEnv");
var env = new Proxy(_envShim, {
  get(_, prop) {
    const env2 = _getEnv();
    return env2[prop] ?? _envShim[prop];
  },
  has(_, prop) {
    const env2 = _getEnv();
    return prop in env2 || prop in _envShim;
  },
  set(_, prop, value) {
    const env2 = _getEnv(true);
    env2[prop] = value;
    return true;
  },
  deleteProperty(_, prop) {
    if (!prop) {
      return false;
    }
    const env2 = _getEnv(true);
    delete env2[prop];
    return true;
  },
  ownKeys() {
    const env2 = _getEnv(true);
    return Object.keys(env2);
  }
});
var nodeENV = typeof process !== "undefined" && process.env && process.env.NODE_ENV || "";
var isDevelopment = nodeENV === "dev" || nodeENV === "development";
function getEnvVar(key, fallback) {
  if (typeof process !== "undefined" && process.env) {
    return process.env[key] ?? fallback;
  }
  if (typeof Deno !== "undefined") {
    return Deno.env.get(key) ?? fallback;
  }
  if (typeof Bun !== "undefined") {
    return Bun.env[key] ?? fallback;
  }
  return fallback;
}
__name(getEnvVar, "getEnvVar");

// node_modules/@better-auth/utils/dist/base64.mjs
function getAlphabet(urlSafe) {
  return urlSafe ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}
__name(getAlphabet, "getAlphabet");
function base64Encode(data, alphabet, padding) {
  let result = "";
  let buffer = 0;
  let shift = 0;
  for (const byte of data) {
    buffer = buffer << 8 | byte;
    shift += 8;
    while (shift >= 6) {
      shift -= 6;
      result += alphabet[buffer >> shift & 63];
    }
  }
  if (shift > 0) {
    result += alphabet[buffer << 6 - shift & 63];
  }
  if (padding) {
    const padCount = (4 - result.length % 4) % 4;
    result += "=".repeat(padCount);
  }
  return result;
}
__name(base64Encode, "base64Encode");
function base64Decode(data, alphabet) {
  const decodeMap = /* @__PURE__ */ new Map();
  for (let i = 0; i < alphabet.length; i++) {
    decodeMap.set(alphabet[i], i);
  }
  const result = [];
  let buffer = 0;
  let bitsCollected = 0;
  for (const char of data) {
    if (char === "=")
      break;
    const value = decodeMap.get(char);
    if (value === void 0) {
      throw new Error(`Invalid Base64 character: ${char}`);
    }
    buffer = buffer << 6 | value;
    bitsCollected += 6;
    if (bitsCollected >= 8) {
      bitsCollected -= 8;
      result.push(buffer >> bitsCollected & 255);
    }
  }
  return Uint8Array.from(result);
}
__name(base64Decode, "base64Decode");
var base642 = {
  encode(data, options = {}) {
    const alphabet = getAlphabet(false);
    const buffer = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
    return base64Encode(buffer, alphabet, options.padding ?? true);
  },
  decode(data) {
    if (typeof data !== "string") {
      data = new TextDecoder().decode(data);
    }
    const urlSafe = data.includes("-") || data.includes("_");
    const alphabet = getAlphabet(urlSafe);
    return base64Decode(data, alphabet);
  }
};
var base64Url = {
  encode(data, options = {}) {
    const alphabet = getAlphabet(true);
    const buffer = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
    return base64Encode(buffer, alphabet, options.padding ?? true);
  },
  decode(data) {
    const urlSafe = data.includes("-") || data.includes("_");
    const alphabet = getAlphabet(urlSafe);
    return base64Decode(data, alphabet);
  }
};

// node_modules/@better-auth/utils/dist/hex.mjs
var hexadecimal = "0123456789abcdef";
var hex = {
  encode: /* @__PURE__ */ __name((data) => {
    if (typeof data === "string") {
      data = new TextEncoder().encode(data);
    }
    if (data.byteLength === 0) {
      return "";
    }
    const buffer = new Uint8Array(data);
    let result = "";
    for (const byte of buffer) {
      result += byte.toString(16).padStart(2, "0");
    }
    return result;
  }, "encode"),
  decode: /* @__PURE__ */ __name((data) => {
    if (!data) {
      return "";
    }
    if (typeof data === "string") {
      if (data.length % 2 !== 0) {
        throw new Error("Invalid hexadecimal string");
      }
      if (!new RegExp(`^[${hexadecimal}]+$`).test(data)) {
        throw new Error("Invalid hexadecimal string");
      }
      const result = new Uint8Array(data.length / 2);
      for (let i = 0; i < data.length; i += 2) {
        result[i / 2] = parseInt(data.slice(i, i + 2), 16);
      }
      return new TextDecoder().decode(result);
    }
    return new TextDecoder().decode(data);
  }, "decode")
};

// node_modules/@better-auth/utils/dist/hmac.mjs
var createHMAC = /* @__PURE__ */ __name((algorithm2 = "SHA-256", encoding = "none") => {
  const hmac = {
    importKey: /* @__PURE__ */ __name(async (key, keyUsage) => {
      return getWebcryptoSubtle().importKey(
        "raw",
        typeof key === "string" ? new TextEncoder().encode(key) : key,
        { name: "HMAC", hash: { name: algorithm2 } },
        false,
        [keyUsage]
      );
    }, "importKey"),
    sign: /* @__PURE__ */ __name(async (hmacKey, data) => {
      if (typeof hmacKey === "string") {
        hmacKey = await hmac.importKey(hmacKey, "sign");
      }
      const signature = await getWebcryptoSubtle().sign(
        "HMAC",
        hmacKey,
        typeof data === "string" ? new TextEncoder().encode(data) : data
      );
      if (encoding === "hex") {
        return hex.encode(signature);
      }
      if (encoding === "base64" || encoding === "base64url" || encoding === "base64urlnopad") {
        return base64Url.encode(signature, {
          padding: encoding !== "base64urlnopad"
        });
      }
      return signature;
    }, "sign"),
    verify: /* @__PURE__ */ __name(async (hmacKey, data, signature) => {
      if (typeof hmacKey === "string") {
        hmacKey = await hmac.importKey(hmacKey, "verify");
      }
      if (encoding === "hex") {
        signature = hex.decode(signature);
      }
      if (encoding === "base64" || encoding === "base64url" || encoding === "base64urlnopad") {
        signature = await base642.decode(signature);
      }
      return getWebcryptoSubtle().verify(
        "HMAC",
        hmacKey,
        typeof signature === "string" ? new TextEncoder().encode(signature) : signature,
        typeof data === "string" ? new TextEncoder().encode(data) : data
      );
    }, "verify")
  };
  return hmac;
}, "createHMAC");

// node_modules/better-auth/dist/shared/better-auth.DgGir396.mjs
var COLORS_2 = 1;
var COLORS_16 = 4;
var COLORS_256 = 8;
var COLORS_16m = 24;
var TERM_ENVS = {
  eterm: COLORS_16,
  cons25: COLORS_16,
  console: COLORS_16,
  cygwin: COLORS_16,
  dtterm: COLORS_16,
  gnome: COLORS_16,
  hurd: COLORS_16,
  jfbterm: COLORS_16,
  konsole: COLORS_16,
  kterm: COLORS_16,
  mlterm: COLORS_16,
  mosh: COLORS_16m,
  putty: COLORS_16,
  st: COLORS_16,
  // http://lists.schmorp.de/pipermail/rxvt-unicode/2016q2/002261.html
  "rxvt-unicode-24bit": COLORS_16m,
  // https://bugs.launchpad.net/terminator/+bug/1030562
  terminator: COLORS_16m,
  "xterm-kitty": COLORS_16m
};
var CI_ENVS_MAP = new Map(
  Object.entries({
    APPVEYOR: COLORS_256,
    BUILDKITE: COLORS_256,
    CIRCLECI: COLORS_16m,
    DRONE: COLORS_256,
    GITEA_ACTIONS: COLORS_16m,
    GITHUB_ACTIONS: COLORS_16m,
    GITLAB_CI: COLORS_256,
    TRAVIS: COLORS_256
  })
);
var TERM_ENVS_REG_EXP = [
  /ansi/,
  /color/,
  /linux/,
  /direct/,
  /^con[0-9]*x[0-9]/,
  /^rxvt/,
  /^screen/,
  /^xterm/,
  /^vt100/,
  /^vt220/
];
function getColorDepth() {
  if (getEnvVar("FORCE_COLOR") !== void 0) {
    switch (getEnvVar("FORCE_COLOR")) {
      case "":
      case "1":
      case "true":
        return COLORS_16;
      case "2":
        return COLORS_256;
      case "3":
        return COLORS_16m;
      default:
        return COLORS_2;
    }
  }
  if (getEnvVar("NODE_DISABLE_COLORS") !== void 0 && getEnvVar("NODE_DISABLE_COLORS") !== "" || // See https://no-color.org/
  getEnvVar("NO_COLOR") !== void 0 && getEnvVar("NO_COLOR") !== "" || // The "dumb" special terminal, as defined by terminfo, doesn't support
  // ANSI color control codes.
  // See https://invisible-island.net/ncurses/terminfo.ti.html#toc-_Specials
  getEnvVar("TERM") === "dumb") {
    return COLORS_2;
  }
  if (typeof process !== "undefined" && process.platform === "win32") {
    return COLORS_16m;
  }
  if (getEnvVar("TMUX")) {
    return COLORS_16m;
  }
  if ("TF_BUILD" in env && "AGENT_NAME" in env) {
    return COLORS_16;
  }
  if ("CI" in env) {
    for (const { 0: envName, 1: colors2 } of CI_ENVS_MAP) {
      if (envName in env) {
        return colors2;
      }
    }
    if (getEnvVar("CI_NAME") === "codeship") {
      return COLORS_256;
    }
    return COLORS_2;
  }
  if ("TEAMCITY_VERSION" in env) {
    return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.exec(
      getEnvVar("TEAMCITY_VERSION")
    ) !== null ? COLORS_16 : COLORS_2;
  }
  switch (getEnvVar("TERM_PROGRAM")) {
    case "iTerm.app":
      if (!getEnvVar("TERM_PROGRAM_VERSION") || /^[0-2]\./.exec(getEnvVar("TERM_PROGRAM_VERSION")) !== null) {
        return COLORS_256;
      }
      return COLORS_16m;
    case "HyperTerm":
    case "MacTerm":
      return COLORS_16m;
    case "Apple_Terminal":
      return COLORS_256;
  }
  if (getEnvVar("COLORTERM") === "truecolor" || getEnvVar("COLORTERM") === "24bit") {
    return COLORS_16m;
  }
  if (getEnvVar("TERM")) {
    if (/truecolor/.exec(getEnvVar("TERM")) !== null) {
      return COLORS_16m;
    }
    if (/^xterm-256/.exec(getEnvVar("TERM")) !== null) {
      return COLORS_256;
    }
    const termEnv = getEnvVar("TERM").toLowerCase();
    if (TERM_ENVS[termEnv]) {
      return TERM_ENVS[termEnv];
    }
    if (TERM_ENVS_REG_EXP.some((term) => term.exec(termEnv) !== null)) {
      return COLORS_16;
    }
  }
  if (getEnvVar("COLORTERM")) {
    return COLORS_16;
  }
  return COLORS_2;
}
__name(getColorDepth, "getColorDepth");
var colors = {
  reset: "\x1B[0m",
  bright: "\x1B[1m",
  dim: "\x1B[2m",
  fg: {
    red: "\x1B[31m",
    green: "\x1B[32m",
    yellow: "\x1B[33m",
    blue: "\x1B[34m",
    magenta: "\x1B[35m"
  },
  bg: {
    black: "\x1B[40m"
  }
};
var levels = ["info", "success", "warn", "error", "debug"];
function shouldPublishLog(currentLogLevel, logLevel) {
  return levels.indexOf(logLevel) <= levels.indexOf(currentLogLevel);
}
__name(shouldPublishLog, "shouldPublishLog");
var levelColors = {
  info: colors.fg.blue,
  success: colors.fg.green,
  warn: colors.fg.yellow,
  error: colors.fg.red,
  debug: colors.fg.magenta
};
var formatMessage = /* @__PURE__ */ __name((level, message2, colorsEnabled) => {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  if (colorsEnabled) {
    return `${colors.dim}${timestamp}${colors.reset} ${levelColors[level]}${level.toUpperCase()}${colors.reset} ${colors.bright}[Better Auth]:${colors.reset} ${message2}`;
  }
  return `${timestamp} ${level.toUpperCase()} [Better Auth]: ${message2}`;
}, "formatMessage");
var createLogger = /* @__PURE__ */ __name((options) => {
  const enabled = options?.disabled !== true;
  const logLevel = options?.level ?? "error";
  const isDisableColorsSpecified = options?.disableColors !== void 0;
  const colorsEnabled = isDisableColorsSpecified ? !options.disableColors : getColorDepth() !== 1;
  const LogFunc = /* @__PURE__ */ __name((level, message2, args = []) => {
    if (!enabled || !shouldPublishLog(logLevel, level)) {
      return;
    }
    const formattedMessage = formatMessage(level, message2, colorsEnabled);
    if (!options || typeof options.log !== "function") {
      if (level === "error") {
        console.error(formattedMessage, ...args);
      } else if (level === "warn") {
        console.warn(formattedMessage, ...args);
      } else {
        console.log(formattedMessage, ...args);
      }
      return;
    }
    options.log(level === "success" ? "info" : level, message2, ...args);
  }, "LogFunc");
  const logger2 = Object.fromEntries(
    levels.map((level) => [
      level,
      (...[message2, ...args]) => LogFunc(level, message2, args)
    ])
  );
  return {
    ...logger2,
    get level() {
      return logLevel;
    }
  };
}, "createLogger");
var logger = createLogger();

// node_modules/better-auth/dist/shared/better-auth.BTrSrKsi.mjs
function safeJSONParse(data) {
  function reviver(_, value) {
    if (typeof value === "string") {
      const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
      if (iso8601Regex.test(value)) {
        const date5 = new Date(value);
        if (!isNaN(date5.getTime())) {
          return date5;
        }
      }
    }
    return value;
  }
  __name(reviver, "reviver");
  try {
    if (typeof data !== "string") {
      return data;
    }
    return JSON.parse(data, reviver);
  } catch (e) {
    logger.error("Error parsing JSON", { error: e });
    return null;
  }
}
__name(safeJSONParse, "safeJSONParse");

// node_modules/better-auth/dist/shared/better-auth.BRFtaovt.mjs
function getOrigin(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.origin;
  } catch (error3) {
    return null;
  }
}
__name(getOrigin, "getOrigin");
function getProtocol(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol;
  } catch (error3) {
    return null;
  }
}
__name(getProtocol, "getProtocol");
function getHost(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.host;
  } catch (error3) {
    return url;
  }
}
__name(getHost, "getHost");

// node_modules/@better-auth/utils/dist/binary.mjs
var decoders = /* @__PURE__ */ new Map();
var encoder = new TextEncoder();
var binary = {
  decode: /* @__PURE__ */ __name((data, encoding = "utf-8") => {
    if (!decoders.has(encoding)) {
      decoders.set(encoding, new TextDecoder(encoding));
    }
    const decoder2 = decoders.get(encoding);
    return decoder2.decode(data);
  }, "decode"),
  encode: encoder.encode
};

// node_modules/better-auth/dist/shared/better-auth.DiMXeqeq.mjs
var s = 1e3;
var m = s * 60;
var h = m * 60;
var d = h * 24;
var w = d * 7;
var y = d * 365.25;
var mo = y / 12;
function ms(value, options) {
  if (typeof value === "string") return parse3(value);
  else if (typeof value === "number") return format(value);
  throw new Error(`Value provided to ms() must be a string or number. value=${JSON.stringify(value)}`);
}
__name(ms, "ms");
function parse3(str) {
  if (typeof str !== "string" || str.length === 0 || str.length > 100) throw new Error(`Value provided to ms.parse() must be a string with length between 1 and 99. value=${JSON.stringify(str)}`);
  const match = /^(?<value>-?\d*\.?\d+) *(?<unit>milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)?$/i.exec(str);
  if (!match?.groups) return NaN;
  const { value, unit = "ms" } = match.groups;
  const n = parseFloat(value);
  const matchUnit = unit.toLowerCase();
  switch (matchUnit) {
    case "years":
    case "year":
    case "yrs":
    case "yr":
    case "y":
      return n * y;
    case "months":
    case "month":
    case "mo":
      return n * mo;
    case "weeks":
    case "week":
    case "w":
      return n * w;
    case "days":
    case "day":
    case "d":
      return n * d;
    case "hours":
    case "hour":
    case "hrs":
    case "hr":
    case "h":
      return n * h;
    case "minutes":
    case "minute":
    case "mins":
    case "min":
    case "m":
      return n * m;
    case "seconds":
    case "second":
    case "secs":
    case "sec":
    case "s":
      return n * s;
    case "milliseconds":
    case "millisecond":
    case "msecs":
    case "msec":
    case "ms":
      return n;
    default:
      throw new Error(`Unknown unit "${matchUnit}" provided to ms.parse(). value=${JSON.stringify(str)}`);
  }
}
__name(parse3, "parse");
function fmtShort(ms$1) {
  const msAbs = Math.abs(ms$1);
  if (msAbs >= y) return `${Math.round(ms$1 / y)}y`;
  if (msAbs >= mo) return `${Math.round(ms$1 / mo)}mo`;
  if (msAbs >= w) return `${Math.round(ms$1 / w)}w`;
  if (msAbs >= d) return `${Math.round(ms$1 / d)}d`;
  if (msAbs >= h) return `${Math.round(ms$1 / h)}h`;
  if (msAbs >= m) return `${Math.round(ms$1 / m)}m`;
  if (msAbs >= s) return `${Math.round(ms$1 / s)}s`;
  return `${ms$1}ms`;
}
__name(fmtShort, "fmtShort");
function format(ms$1, options) {
  if (typeof ms$1 !== "number" || !Number.isFinite(ms$1)) throw new Error("Value provided to ms.format() must be of type number.");
  return fmtShort(ms$1);
}
__name(format, "format");
async function setCookieCache(ctx, session, dontRememberMe) {
  const shouldStoreSessionDataInCookie = ctx.context.options.session?.cookieCache?.enabled;
  if (shouldStoreSessionDataInCookie) {
    const filteredSession = Object.entries(session.session).reduce(
      (acc, [key, value]) => {
        const fieldConfig = ctx.context.options.session?.additionalFields?.[key];
        if (!fieldConfig || fieldConfig.returned !== false) {
          acc[key] = value;
        }
        return acc;
      },
      {}
    );
    const sessionData = { session: filteredSession, user: session.user };
    const options = {
      ...ctx.context.authCookies.sessionData.options,
      maxAge: dontRememberMe ? void 0 : ctx.context.authCookies.sessionData.options.maxAge
    };
    const expiresAtDate = getDate(options.maxAge || 60, "sec").getTime();
    const data = base64Url.encode(
      JSON.stringify({
        session: sessionData,
        expiresAt: expiresAtDate,
        signature: await createHMAC("SHA-256", "base64urlnopad").sign(
          ctx.context.secret,
          JSON.stringify({
            ...sessionData,
            expiresAt: expiresAtDate
          })
        )
      }),
      {
        padding: false
      }
    );
    if (data.length > 4093) {
      ctx.context?.logger?.error(
        `Session data exceeds cookie size limit (${data.length} bytes > 4093 bytes). Consider reducing session data size or disabling cookie cache. Session will not be cached in cookie.`
      );
      return;
    }
    ctx.setCookie(ctx.context.authCookies.sessionData.name, data, options);
  }
}
__name(setCookieCache, "setCookieCache");
async function setSessionCookie(ctx, session, dontRememberMe, overrides) {
  const dontRememberMeCookie = await ctx.getSignedCookie(
    ctx.context.authCookies.dontRememberToken.name,
    ctx.context.secret
  );
  dontRememberMe = dontRememberMe !== void 0 ? dontRememberMe : !!dontRememberMeCookie;
  const options = ctx.context.authCookies.sessionToken.options;
  const maxAge = dontRememberMe ? void 0 : ctx.context.sessionConfig.expiresIn;
  await ctx.setSignedCookie(
    ctx.context.authCookies.sessionToken.name,
    session.session.token,
    ctx.context.secret,
    {
      ...options,
      maxAge,
      ...overrides
    }
  );
  if (dontRememberMe) {
    await ctx.setSignedCookie(
      ctx.context.authCookies.dontRememberToken.name,
      "true",
      ctx.context.secret,
      ctx.context.authCookies.dontRememberToken.options
    );
  }
  await setCookieCache(ctx, session, dontRememberMe);
  ctx.context.setNewSession(session);
  if (ctx.context.options.secondaryStorage) {
    await ctx.context.secondaryStorage?.set(
      session.session.token,
      JSON.stringify({
        user: session.user,
        session: session.session
      }),
      Math.floor(
        (new Date(session.session.expiresAt).getTime() - Date.now()) / 1e3
      )
    );
  }
}
__name(setSessionCookie, "setSessionCookie");
function deleteSessionCookie(ctx, skipDontRememberMe) {
  ctx.setCookie(ctx.context.authCookies.sessionToken.name, "", {
    ...ctx.context.authCookies.sessionToken.options,
    maxAge: 0
  });
  ctx.setCookie(ctx.context.authCookies.sessionData.name, "", {
    ...ctx.context.authCookies.sessionData.options,
    maxAge: 0
  });
  if (!skipDontRememberMe) {
    ctx.setCookie(ctx.context.authCookies.dontRememberToken.name, "", {
      ...ctx.context.authCookies.dontRememberToken.options,
      maxAge: 0
    });
  }
}
__name(deleteSessionCookie, "deleteSessionCookie");

// node_modules/better-auth/dist/shared/better-auth.D2xndZ2p.mjs
function defineErrorCodes(codes) {
  return codes;
}
__name(defineErrorCodes, "defineErrorCodes");

// node_modules/better-auth/dist/shared/better-auth.C5vDERgF.mjs
var optionsMiddleware = createMiddleware(async () => {
  return {};
});
var createAuthMiddleware = createMiddleware.create({
  use: [
    optionsMiddleware,
    /**
     * Only use for post hooks
     */
    createMiddleware(async () => {
      return {};
    })
  ]
});
var createAuthEndpoint = createEndpoint2.create({
  use: [optionsMiddleware]
});
var BASE_ERROR_CODES = defineErrorCodes({
  USER_NOT_FOUND: "User not found",
  FAILED_TO_CREATE_USER: "Failed to create user",
  FAILED_TO_CREATE_SESSION: "Failed to create session",
  FAILED_TO_UPDATE_USER: "Failed to update user",
  FAILED_TO_GET_SESSION: "Failed to get session",
  INVALID_PASSWORD: "Invalid password",
  INVALID_EMAIL: "Invalid email",
  INVALID_EMAIL_OR_PASSWORD: "Invalid email or password",
  SOCIAL_ACCOUNT_ALREADY_LINKED: "Social account already linked",
  PROVIDER_NOT_FOUND: "Provider not found",
  INVALID_TOKEN: "Invalid token",
  ID_TOKEN_NOT_SUPPORTED: "id_token not supported",
  FAILED_TO_GET_USER_INFO: "Failed to get user info",
  USER_EMAIL_NOT_FOUND: "User email not found",
  EMAIL_NOT_VERIFIED: "Email not verified",
  PASSWORD_TOO_SHORT: "Password too short",
  PASSWORD_TOO_LONG: "Password too long",
  USER_ALREADY_EXISTS: "User already exists.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "User already exists. Use another email.",
  EMAIL_CAN_NOT_BE_UPDATED: "Email can not be updated",
  CREDENTIAL_ACCOUNT_NOT_FOUND: "Credential account not found",
  SESSION_EXPIRED: "Session expired. Re-authenticate to perform this action.",
  FAILED_TO_UNLINK_LAST_ACCOUNT: "You can't unlink your last account",
  ACCOUNT_NOT_FOUND: "Account not found",
  USER_ALREADY_HAS_PASSWORD: "User already has a password. Provide that to delete the account."
});
var getSessionQuerySchema = optional(
  object({
    /**
     * If cookie cache is enabled, it will disable the cache
     * and fetch the session from the database
     */
    disableCookieCache: coerce_exports.boolean().meta({
      description: "Disable cookie cache and fetch session from database"
    }).optional(),
    disableRefresh: coerce_exports.boolean().meta({
      description: "Disable session refresh. Useful for checking session status, without updating the session"
    }).optional()
  })
);
var getSession = /* @__PURE__ */ __name(() => createAuthEndpoint(
  "/get-session",
  {
    method: "GET",
    query: getSessionQuerySchema,
    requireHeaders: true,
    metadata: {
      openapi: {
        description: "Get the current session",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    session: {
                      $ref: "#/components/schemas/Session"
                    },
                    user: {
                      $ref: "#/components/schemas/User"
                    }
                  },
                  required: ["session", "user"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    try {
      const sessionCookieToken = await ctx.getSignedCookie(
        ctx.context.authCookies.sessionToken.name,
        ctx.context.secret
      );
      if (!sessionCookieToken) {
        return null;
      }
      const sessionDataCookie = ctx.getCookie(
        ctx.context.authCookies.sessionData.name
      );
      const sessionDataPayload = sessionDataCookie ? safeJSONParse(binary.decode(base64Url.decode(sessionDataCookie))) : null;
      if (sessionDataPayload) {
        const isValid = await createHMAC("SHA-256", "base64urlnopad").verify(
          ctx.context.secret,
          JSON.stringify({
            ...sessionDataPayload.session,
            expiresAt: sessionDataPayload.expiresAt
          }),
          sessionDataPayload.signature
        );
        if (!isValid) {
          const dataCookie = ctx.context.authCookies.sessionData.name;
          ctx.setCookie(dataCookie, "", {
            maxAge: 0
          });
          return ctx.json(null);
        }
      }
      const dontRememberMe = await ctx.getSignedCookie(
        ctx.context.authCookies.dontRememberToken.name,
        ctx.context.secret
      );
      if (sessionDataPayload?.session && ctx.context.options.session?.cookieCache?.enabled && !ctx.query?.disableCookieCache) {
        const session2 = sessionDataPayload.session;
        const hasExpired = sessionDataPayload.expiresAt < Date.now() || session2.session.expiresAt < /* @__PURE__ */ new Date();
        if (!hasExpired) {
          ctx.context.session = session2;
          return ctx.json(
            session2
          );
        } else {
          const dataCookie = ctx.context.authCookies.sessionData.name;
          ctx.setCookie(dataCookie, "", {
            maxAge: 0
          });
        }
      }
      const session = await ctx.context.internalAdapter.findSession(sessionCookieToken);
      ctx.context.session = session;
      if (!session || session.session.expiresAt < /* @__PURE__ */ new Date()) {
        deleteSessionCookie(ctx);
        if (session) {
          await ctx.context.internalAdapter.deleteSession(
            session.session.token
          );
        }
        return ctx.json(null);
      }
      if (dontRememberMe || ctx.query?.disableRefresh) {
        return ctx.json(
          session
        );
      }
      const expiresIn = ctx.context.sessionConfig.expiresIn;
      const updateAge = ctx.context.sessionConfig.updateAge;
      const sessionIsDueToBeUpdatedDate = session.session.expiresAt.valueOf() - expiresIn * 1e3 + updateAge * 1e3;
      const shouldBeUpdated = sessionIsDueToBeUpdatedDate <= Date.now();
      if (shouldBeUpdated && (!ctx.query?.disableRefresh || !ctx.context.options.session?.disableSessionRefresh)) {
        const updatedSession = await ctx.context.internalAdapter.updateSession(
          session.session.token,
          {
            expiresAt: getDate(ctx.context.sessionConfig.expiresIn, "sec"),
            updatedAt: /* @__PURE__ */ new Date()
          }
        );
        if (!updatedSession) {
          deleteSessionCookie(ctx);
          return ctx.json(null, { status: 401 });
        }
        const maxAge = (updatedSession.expiresAt.valueOf() - Date.now()) / 1e3;
        await setSessionCookie(
          ctx,
          {
            session: updatedSession,
            user: session.user
          },
          false,
          {
            maxAge
          }
        );
        return ctx.json({
          session: updatedSession,
          user: session.user
        });
      }
      await setCookieCache(ctx, session, !!dontRememberMe);
      return ctx.json(
        session
      );
    } catch (error3) {
      ctx.context.logger.error("INTERNAL_SERVER_ERROR", error3);
      throw new APIError("INTERNAL_SERVER_ERROR", {
        message: BASE_ERROR_CODES.FAILED_TO_GET_SESSION
      });
    }
  }
), "getSession");
var getSessionFromCtx = /* @__PURE__ */ __name(async (ctx, config2) => {
  if (ctx.context.session) {
    return ctx.context.session;
  }
  const session = await getSession()({
    ...ctx,
    asResponse: false,
    headers: ctx.headers,
    returnHeaders: false,
    query: {
      ...config2,
      ...ctx.query
    }
  }).catch((e) => {
    return null;
  });
  ctx.context.session = session;
  return session;
}, "getSessionFromCtx");
var sessionMiddleware = createAuthMiddleware(async (ctx) => {
  const session = await getSessionFromCtx(ctx);
  if (!session?.session) {
    throw new APIError("UNAUTHORIZED");
  }
  return {
    session
  };
});
var sensitiveSessionMiddleware = createAuthMiddleware(async (ctx) => {
  const session = await getSessionFromCtx(ctx, { disableCookieCache: true });
  if (!session?.session) {
    throw new APIError("UNAUTHORIZED");
  }
  return {
    session
  };
});
var requestOnlySessionMiddleware = createAuthMiddleware(
  async (ctx) => {
    const session = await getSessionFromCtx(ctx);
    if (!session?.session && (ctx.request || ctx.headers)) {
      throw new APIError("UNAUTHORIZED");
    }
    return { session };
  }
);
var freshSessionMiddleware = createAuthMiddleware(async (ctx) => {
  const session = await getSessionFromCtx(ctx);
  if (!session?.session) {
    throw new APIError("UNAUTHORIZED");
  }
  if (ctx.context.sessionConfig.freshAge === 0) {
    return {
      session
    };
  }
  const freshAge = ctx.context.sessionConfig.freshAge;
  const lastUpdated = session.session.updatedAt?.valueOf() || session.session.createdAt.valueOf();
  const now = Date.now();
  const isFresh = now - lastUpdated < freshAge * 1e3;
  if (!isFresh) {
    throw new APIError("FORBIDDEN", {
      message: "Session is not fresh"
    });
  }
  return {
    session
  };
});
var revokeSession = createAuthEndpoint(
  "/revoke-session",
  {
    method: "POST",
    body: object({
      token: string2().meta({
        description: "The token to revoke"
      })
    }),
    use: [sensitiveSessionMiddleware],
    requireHeaders: true,
    metadata: {
      openapi: {
        description: "Revoke a single session",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  token: {
                    type: "string",
                    description: "The token to revoke"
                  }
                },
                required: ["token"]
              }
            }
          }
        },
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean",
                      description: "Indicates if the session was revoked successfully"
                    }
                  },
                  required: ["status"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const token = ctx.body.token;
    const findSession = await ctx.context.internalAdapter.findSession(token);
    if (!findSession) {
      throw new APIError("BAD_REQUEST", {
        message: "Session not found"
      });
    }
    if (findSession.session.userId !== ctx.context.session.user.id) {
      throw new APIError("UNAUTHORIZED");
    }
    try {
      await ctx.context.internalAdapter.deleteSession(token);
    } catch (error3) {
      ctx.context.logger.error(
        error3 && typeof error3 === "object" && "name" in error3 ? error3.name : "",
        error3
      );
      throw new APIError("INTERNAL_SERVER_ERROR");
    }
    return ctx.json({
      status: true
    });
  }
);
var revokeSessions = createAuthEndpoint(
  "/revoke-sessions",
  {
    method: "POST",
    use: [sensitiveSessionMiddleware],
    requireHeaders: true,
    metadata: {
      openapi: {
        description: "Revoke all sessions for the user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean",
                      description: "Indicates if all sessions were revoked successfully"
                    }
                  },
                  required: ["status"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    try {
      await ctx.context.internalAdapter.deleteSessions(
        ctx.context.session.user.id
      );
    } catch (error3) {
      ctx.context.logger.error(
        error3 && typeof error3 === "object" && "name" in error3 ? error3.name : "",
        error3
      );
      throw new APIError("INTERNAL_SERVER_ERROR");
    }
    return ctx.json({
      status: true
    });
  }
);
var revokeOtherSessions = createAuthEndpoint(
  "/revoke-other-sessions",
  {
    method: "POST",
    requireHeaders: true,
    use: [sensitiveSessionMiddleware],
    metadata: {
      openapi: {
        description: "Revoke all other sessions for the user except the current one",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean",
                      description: "Indicates if all other sessions were revoked successfully"
                    }
                  },
                  required: ["status"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const session = ctx.context.session;
    if (!session.user) {
      throw new APIError("UNAUTHORIZED");
    }
    const sessions = await ctx.context.internalAdapter.listSessions(
      session.user.id
    );
    const activeSessions = sessions.filter((session2) => {
      return session2.expiresAt > /* @__PURE__ */ new Date();
    });
    const otherSessions = activeSessions.filter(
      (session2) => session2.token !== ctx.context.session.session.token
    );
    await Promise.all(
      otherSessions.map(
        (session2) => ctx.context.internalAdapter.deleteSession(session2.token)
      )
    );
    return ctx.json({
      status: true
    });
  }
);

// node_modules/@better-auth/utils/dist/hash.mjs
function createHash(algorithm2, encoding) {
  return {
    digest: /* @__PURE__ */ __name(async (input) => {
      const encoder3 = new TextEncoder();
      const data = typeof input === "string" ? encoder3.encode(input) : input;
      const hashBuffer = await getWebcryptoSubtle().digest(algorithm2, data);
      if (encoding === "hex") {
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
        return hashHex;
      }
      if (encoding === "base64" || encoding === "base64url" || encoding === "base64urlnopad") {
        if (encoding.includes("url")) {
          return base64Url.encode(hashBuffer, {
            padding: encoding !== "base64urlnopad"
          });
        }
        const hashBase64 = base642.encode(hashBuffer);
        return hashBase64;
      }
      return hashBuffer;
    }, "digest")
  };
}
__name(createHash, "createHash");

// node_modules/@noble/ciphers/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
__name(isBytes, "isBytes");
function abool(b) {
  if (typeof b !== "boolean") throw new Error(`boolean expected, not ${b}`);
}
__name(abool, "abool");
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("positive integer expected, got " + n);
}
__name(anumber, "anumber");
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
__name(abytes, "abytes");
function aexists(instance, checkFinished = true) {
  if (instance.destroyed) throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished) throw new Error("Hash#digest() has already been called");
}
__name(aexists, "aexists");
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
__name(aoutput, "aoutput");
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
__name(u32, "u32");
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
__name(clean, "clean");
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
__name(createView, "createView");
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([
  287454020
]).buffer)[0] === 68)();
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({
  length: 256
}, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin) return bytes.toHex();
  let hex2 = "";
  for (let i = 0; i < bytes.length; i++) {
    hex2 += hexes[bytes[i]];
  }
  return hex2;
}
__name(bytesToHex, "bytesToHex");
var asciis = {
  _0: 48,
  _9: 57,
  A: 65,
  F: 70,
  a: 97,
  f: 102
};
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10);
  return;
}
__name(asciiToBase16, "asciiToBase16");
function hexToBytes(hex2) {
  if (typeof hex2 !== "string") throw new Error("hex string expected, got " + typeof hex2);
  if (hasHexBuiltin) return Uint8Array.fromHex(hex2);
  const hl = hex2.length;
  const al = hl / 2;
  if (hl % 2) throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array2 = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex2.charCodeAt(hi));
    const n2 = asciiToBase16(hex2.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex2[hi] + hex2[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array2[ai] = n1 * 16 + n2;
  }
  return array2;
}
__name(hexToBytes, "hexToBytes");
function utf8ToBytes(str) {
  if (typeof str !== "string") throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
__name(utf8ToBytes, "utf8ToBytes");
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
__name(concatBytes, "concatBytes");
function checkOpts(defaults, opts) {
  if (opts == null || typeof opts !== "object") throw new Error("options must be defined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
__name(checkOpts, "checkOpts");
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
__name(equalBytes, "equalBytes");
var wrapCipher = /* @__PURE__ */ __name(/* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes(key, void 0, "key");
    if (!isLE) throw new Error("Non little-endian hardware is not yet supported");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      abytes(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
    }
    const tagl = params.tagLength;
    if (tagl && args[1] !== void 0) abytes(args[1], void 0, "AAD");
    const cipher = constructor(key, ...args);
    const checkOutput = /* @__PURE__ */ __name((fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2) throw new Error("cipher output not supported");
        abytes(output, void 0, "output");
      }
    }, "checkOutput");
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called) throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes(data);
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes(data);
        if (tagl && data.length < tagl) throw new Error('"ciphertext" expected length bigger than tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  __name(wrappedCipher, "wrappedCipher");
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
}, "wrapCipher");
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0) return new Uint8Array(expectedLength);
  if (out.length !== expectedLength) throw new Error('"output" expected Uint8Array of length ' + expectedLength + ", got: " + out.length);
  if (onlyAligned && !isAligned32(out)) throw new Error("invalid output, must be aligned");
  return out;
}
__name(getOutput, "getOutput");
function u64Lengths(dataLength, aadLength, isLE2) {
  abool(isLE2);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE2);
  view.setBigUint64(8, BigInt(dataLength), isLE2);
  return num;
}
__name(u64Lengths, "u64Lengths");
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
__name(isAligned32, "isAligned32");
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
__name(copyBytes, "copyBytes");
function randomBytes(bytesLength = 32) {
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function") throw new Error("crypto.getRandomValues must be defined");
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
__name(randomBytes, "randomBytes");
function managedNonce(fn, randomBytes_ = randomBytes) {
  const { nonceLength } = fn;
  anumber(nonceLength);
  const addNonce = /* @__PURE__ */ __name((nonce, ciphertext) => {
    const out = concatBytes(nonce, ciphertext);
    ciphertext.fill(0);
    return out;
  }, "addNonce");
  return (key, ...args) => ({
    encrypt(plaintext) {
      abytes(plaintext);
      const nonce = randomBytes_(nonceLength);
      const encrypted = fn(key, nonce, ...args).encrypt(plaintext);
      if (encrypted instanceof Promise) return encrypted.then((ct) => addNonce(nonce, ct));
      return addNonce(nonce, encrypted);
    },
    decrypt(ciphertext) {
      abytes(ciphertext);
      const nonce = ciphertext.subarray(0, nonceLength);
      const decrypted = ciphertext.subarray(nonceLength);
      return fn(key, nonce, ...args).decrypt(decrypted);
    }
  });
}
__name(managedNonce, "managedNonce");

// node_modules/@noble/ciphers/_arx.js
var encodeStr = /* @__PURE__ */ __name((str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0)), "encodeStr");
var sigma16 = encodeStr("expand 16-byte k");
var sigma32 = encodeStr("expand 32-byte k");
var sigma16_32 = u32(sigma16);
var sigma32_32 = u32(sigma32);
function rotl(a, b) {
  return a << b | a >>> 32 - b;
}
__name(rotl, "rotl");
function isAligned322(b) {
  return b.byteOffset % 4 === 0;
}
__name(isAligned322, "isAligned32");
var BLOCK_LEN = 64;
var BLOCK_LEN32 = 16;
var MAX_COUNTER = 2 ** 32 - 1;
var U32_EMPTY = Uint32Array.of();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  const isAligned = isAligned322(data) && isAligned322(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds);
    if (counter >= MAX_COUNTER) throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0) throw new Error("arx: invalid block position");
      for (let j = 0, posj; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}
__name(runCipher, "runCipher");
function createCipher(core, opts) {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({
    allowShortKeys: false,
    counterLength: 8,
    counterRight: false,
    rounds: 20
  }, opts);
  if (typeof core !== "function") throw new Error("core must be a function");
  anumber(counterLength);
  anumber(rounds);
  abool(counterRight);
  abool(allowShortKeys);
  return (key, nonce, data, output, counter = 0) => {
    abytes(key, void 0, "key");
    abytes(nonce, void 0, "nonce");
    abytes(data, void 0, "data");
    const len = data.length;
    if (output === void 0) output = new Uint8Array(len);
    abytes(output, void 0, "output");
    anumber(counter);
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error("arx: counter overflow");
    if (output.length < len) throw new Error(`arx: output (${output.length}) is shorter than data (${len})`);
    const toClean = [];
    let l = key.length;
    let k;
    let sigma;
    if (l === 32) {
      toClean.push(k = copyBytes(key));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      abytes(key, 32, "arx key");
      throw new Error("invalid key size");
    }
    if (!isAligned322(nonce)) toClean.push(nonce = copyBytes(nonce));
    const k32 = u32(k);
    if (extendNonceFn) {
      if (nonce.length !== 24) throw new Error(`arx: extended nonce must be 24 bytes`);
      extendNonceFn(sigma, k32, u32(nonce.subarray(0, 16)), k32);
      nonce = nonce.subarray(16);
    }
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length) throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = u32(nonce);
    runCipher(core, sigma, k32, n32, data, output, counter, rounds);
    clean(...toClean);
    return output;
  };
}
__name(createCipher, "createCipher");

// node_modules/@noble/ciphers/_poly1305.js
function u8to16(a, i) {
  return a[i++] & 255 | (a[i++] & 255) << 8;
}
__name(u8to16, "u8to16");
var Poly1305 = class {
  static {
    __name(this, "Poly1305");
  }
  blockLen = 16;
  outputLen = 16;
  buffer = new Uint8Array(16);
  r = new Uint16Array(10);
  h = new Uint16Array(10);
  pad = new Uint16Array(8);
  pos = 0;
  finished = false;
  // Can be speed-up using BigUint64Array, at the cost of complexity
  constructor(key) {
    key = copyBytes(abytes(key, 32, "key"));
    const t0 = u8to16(key, 0);
    const t1 = u8to16(key, 2);
    const t2 = u8to16(key, 4);
    const t3 = u8to16(key, 6);
    const t4 = u8to16(key, 8);
    const t5 = u8to16(key, 10);
    const t6 = u8to16(key, 12);
    const t7 = u8to16(key, 14);
    this.r[0] = t0 & 8191;
    this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
    this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
    this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
    this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
    this.r[5] = t4 >>> 1 & 8190;
    this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
    this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
    this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
    this.r[9] = t7 >>> 5 & 127;
    for (let i = 0; i < 8; i++) this.pad[i] = u8to16(key, 16 + 2 * i);
  }
  process(data, offset, isLast = false) {
    const hibit = isLast ? 0 : 1 << 11;
    const { h: h2, r } = this;
    const r0 = r[0];
    const r1 = r[1];
    const r2 = r[2];
    const r3 = r[3];
    const r4 = r[4];
    const r5 = r[5];
    const r6 = r[6];
    const r7 = r[7];
    const r8 = r[8];
    const r9 = r[9];
    const t0 = u8to16(data, offset + 0);
    const t1 = u8to16(data, offset + 2);
    const t2 = u8to16(data, offset + 4);
    const t3 = u8to16(data, offset + 6);
    const t4 = u8to16(data, offset + 8);
    const t5 = u8to16(data, offset + 10);
    const t6 = u8to16(data, offset + 12);
    const t7 = u8to16(data, offset + 14);
    let h0 = h2[0] + (t0 & 8191);
    let h1 = h2[1] + ((t0 >>> 13 | t1 << 3) & 8191);
    let h22 = h2[2] + ((t1 >>> 10 | t2 << 6) & 8191);
    let h3 = h2[3] + ((t2 >>> 7 | t3 << 9) & 8191);
    let h4 = h2[4] + ((t3 >>> 4 | t4 << 12) & 8191);
    let h5 = h2[5] + (t4 >>> 1 & 8191);
    let h6 = h2[6] + ((t4 >>> 14 | t5 << 2) & 8191);
    let h7 = h2[7] + ((t5 >>> 11 | t6 << 5) & 8191);
    let h8 = h2[8] + ((t6 >>> 8 | t7 << 8) & 8191);
    let h9 = h2[9] + (t7 >>> 5 | hibit);
    let c = 0;
    let d0 = c + h0 * r0 + h1 * (5 * r9) + h22 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
    c = d0 >>> 13;
    d0 &= 8191;
    d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
    c += d0 >>> 13;
    d0 &= 8191;
    let d1 = c + h0 * r1 + h1 * r0 + h22 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
    c = d1 >>> 13;
    d1 &= 8191;
    d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
    c += d1 >>> 13;
    d1 &= 8191;
    let d2 = c + h0 * r2 + h1 * r1 + h22 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
    c = d2 >>> 13;
    d2 &= 8191;
    d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
    c += d2 >>> 13;
    d2 &= 8191;
    let d3 = c + h0 * r3 + h1 * r2 + h22 * r1 + h3 * r0 + h4 * (5 * r9);
    c = d3 >>> 13;
    d3 &= 8191;
    d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
    c += d3 >>> 13;
    d3 &= 8191;
    let d4 = c + h0 * r4 + h1 * r3 + h22 * r2 + h3 * r1 + h4 * r0;
    c = d4 >>> 13;
    d4 &= 8191;
    d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
    c += d4 >>> 13;
    d4 &= 8191;
    let d5 = c + h0 * r5 + h1 * r4 + h22 * r3 + h3 * r2 + h4 * r1;
    c = d5 >>> 13;
    d5 &= 8191;
    d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
    c += d5 >>> 13;
    d5 &= 8191;
    let d6 = c + h0 * r6 + h1 * r5 + h22 * r4 + h3 * r3 + h4 * r2;
    c = d6 >>> 13;
    d6 &= 8191;
    d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
    c += d6 >>> 13;
    d6 &= 8191;
    let d7 = c + h0 * r7 + h1 * r6 + h22 * r5 + h3 * r4 + h4 * r3;
    c = d7 >>> 13;
    d7 &= 8191;
    d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
    c += d7 >>> 13;
    d7 &= 8191;
    let d8 = c + h0 * r8 + h1 * r7 + h22 * r6 + h3 * r5 + h4 * r4;
    c = d8 >>> 13;
    d8 &= 8191;
    d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
    c += d8 >>> 13;
    d8 &= 8191;
    let d9 = c + h0 * r9 + h1 * r8 + h22 * r7 + h3 * r6 + h4 * r5;
    c = d9 >>> 13;
    d9 &= 8191;
    d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    c += d9 >>> 13;
    d9 &= 8191;
    c = (c << 2) + c | 0;
    c = c + d0 | 0;
    d0 = c & 8191;
    c = c >>> 13;
    d1 += c;
    h2[0] = d0;
    h2[1] = d1;
    h2[2] = d2;
    h2[3] = d3;
    h2[4] = d4;
    h2[5] = d5;
    h2[6] = d6;
    h2[7] = d7;
    h2[8] = d8;
    h2[9] = d9;
  }
  finalize() {
    const { h: h2, pad } = this;
    const g = new Uint16Array(10);
    let c = h2[1] >>> 13;
    h2[1] &= 8191;
    for (let i = 2; i < 10; i++) {
      h2[i] += c;
      c = h2[i] >>> 13;
      h2[i] &= 8191;
    }
    h2[0] += c * 5;
    c = h2[0] >>> 13;
    h2[0] &= 8191;
    h2[1] += c;
    c = h2[1] >>> 13;
    h2[1] &= 8191;
    h2[2] += c;
    g[0] = h2[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 8191;
    for (let i = 1; i < 10; i++) {
      g[i] = h2[i] + c;
      c = g[i] >>> 13;
      g[i] &= 8191;
    }
    g[9] -= 1 << 13;
    let mask = (c ^ 1) - 1;
    for (let i = 0; i < 10; i++) g[i] &= mask;
    mask = ~mask;
    for (let i = 0; i < 10; i++) h2[i] = h2[i] & mask | g[i];
    h2[0] = (h2[0] | h2[1] << 13) & 65535;
    h2[1] = (h2[1] >>> 3 | h2[2] << 10) & 65535;
    h2[2] = (h2[2] >>> 6 | h2[3] << 7) & 65535;
    h2[3] = (h2[3] >>> 9 | h2[4] << 4) & 65535;
    h2[4] = (h2[4] >>> 12 | h2[5] << 1 | h2[6] << 14) & 65535;
    h2[5] = (h2[6] >>> 2 | h2[7] << 11) & 65535;
    h2[6] = (h2[7] >>> 5 | h2[8] << 8) & 65535;
    h2[7] = (h2[8] >>> 8 | h2[9] << 5) & 65535;
    let f = h2[0] + pad[0];
    h2[0] = f & 65535;
    for (let i = 1; i < 8; i++) {
      f = (h2[i] + pad[i] | 0) + (f >>> 16) | 0;
      h2[i] = f & 65535;
    }
    clean(g);
  }
  update(data) {
    aexists(this);
    abytes(data);
    data = copyBytes(data);
    const { buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        for (; blockLen <= len - pos; pos += blockLen) this.process(data, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(buffer, 0, false);
        this.pos = 0;
      }
    }
    return this;
  }
  destroy() {
    clean(this.h, this.r, this.buffer, this.pad);
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, h: h2 } = this;
    let { pos } = this;
    if (pos) {
      buffer[pos++] = 1;
      for (; pos < 16; pos++) buffer[pos] = 0;
      this.process(buffer, 0, true);
    }
    this.finalize();
    let opos = 0;
    for (let i = 0; i < 8; i++) {
      out[opos++] = h2[i] >>> 0;
      out[opos++] = h2[i] >>> 8;
    }
    return out;
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
};
function wrapConstructorWithKey(hashCons) {
  const hashC = /* @__PURE__ */ __name((msg, key) => hashCons(key).update(msg).digest(), "hashC");
  const tmp = hashCons(new Uint8Array(32));
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (key) => hashCons(key);
  return hashC;
}
__name(wrapConstructorWithKey, "wrapConstructorWithKey");
var poly1305 = /* @__PURE__ */ (() => wrapConstructorWithKey((key) => new Poly1305(key)))();

// node_modules/@noble/ciphers/chacha.js
function chachaCore(s2, k, n, out, cnt, rounds = 20) {
  let y00 = s2[0], y01 = s2[1], y02 = s2[2], y03 = s2[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = y00 + x00 | 0;
  out[oi++] = y01 + x01 | 0;
  out[oi++] = y02 + x02 | 0;
  out[oi++] = y03 + x03 | 0;
  out[oi++] = y04 + x04 | 0;
  out[oi++] = y05 + x05 | 0;
  out[oi++] = y06 + x06 | 0;
  out[oi++] = y07 + x07 | 0;
  out[oi++] = y08 + x08 | 0;
  out[oi++] = y09 + x09 | 0;
  out[oi++] = y10 + x10 | 0;
  out[oi++] = y11 + x11 | 0;
  out[oi++] = y12 + x12 | 0;
  out[oi++] = y13 + x13 | 0;
  out[oi++] = y14 + x14 | 0;
  out[oi++] = y15 + x15 | 0;
}
__name(chachaCore, "chachaCore");
function hchacha(s2, k, i, out) {
  let x00 = s2[0], x01 = s2[1], x02 = s2[2], x03 = s2[3], x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3], x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7], x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
  for (let r = 0; r < 20; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = x00;
  out[oi++] = x01;
  out[oi++] = x02;
  out[oi++] = x03;
  out[oi++] = x12;
  out[oi++] = x13;
  out[oi++] = x14;
  out[oi++] = x15;
}
__name(hchacha, "hchacha");
var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false
});
var xchacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  extendNonceFn: hchacha,
  allowShortKeys: false
});
var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
var updatePadded = /* @__PURE__ */ __name((h2, msg) => {
  h2.update(msg);
  const leftover = msg.length % 16;
  if (leftover) h2.update(ZEROS16.subarray(leftover));
}, "updatePadded");
var ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(fn, key, nonce, ciphertext, AAD) {
  if (AAD !== void 0) abytes(AAD, void 0, "AAD");
  const authKey = fn(key, nonce, ZEROS32);
  const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);
  const h2 = poly1305.create(authKey);
  if (AAD) updatePadded(h2, AAD);
  updatePadded(h2, ciphertext);
  h2.update(lengths);
  const res = h2.digest();
  clean(authKey, lengths);
  return res;
}
__name(computeTag, "computeTag");
var _poly1305_aead = /* @__PURE__ */ __name((xorStream) => (key, nonce, AAD) => {
  const tagLength = 16;
  return {
    encrypt(plaintext, output) {
      const plength = plaintext.length;
      output = getOutput(plength + tagLength, output, false);
      output.set(plaintext);
      const oPlain = output.subarray(0, -tagLength);
      xorStream(key, nonce, oPlain, oPlain, 1);
      const tag2 = computeTag(xorStream, key, nonce, oPlain, AAD);
      output.set(tag2, plength);
      clean(tag2);
      return output;
    },
    decrypt(ciphertext, output) {
      output = getOutput(ciphertext.length - tagLength, output, false);
      const data = ciphertext.subarray(0, -tagLength);
      const passedTag = ciphertext.subarray(-tagLength);
      const tag2 = computeTag(xorStream, key, nonce, data, AAD);
      if (!equalBytes(passedTag, tag2)) throw new Error("invalid tag");
      output.set(ciphertext.subarray(0, -tagLength));
      xorStream(key, nonce, output, output, 1);
      clean(tag2);
      return output;
    }
  };
}, "_poly1305_aead");
var chacha20poly1305 = /* @__PURE__ */ wrapCipher({
  blockSize: 64,
  nonceLength: 12,
  tagLength: 16
}, _poly1305_aead(chacha20));
var xchacha20poly1305 = /* @__PURE__ */ wrapCipher({
  blockSize: 64,
  nonceLength: 24,
  tagLength: 16
}, _poly1305_aead(xchacha20));

// node_modules/jose/dist/webapi/lib/buffer_utils.js
var encoder2 = new TextEncoder();
var decoder = new TextDecoder();
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf.set(buffer, i);
    i += buffer.length;
  }
  return buf;
}
__name(concat, "concat");

// node_modules/jose/dist/webapi/lib/base64.js
function encodeBase64(input) {
  if (Uint8Array.prototype.toBase64) {
    return input.toBase64();
  }
  const CHUNK_SIZE = 32768;
  const arr = [];
  for (let i = 0; i < input.length; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
  }
  return btoa(arr.join(""));
}
__name(encodeBase64, "encodeBase64");
function decodeBase64(encoded) {
  if (Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(encoded);
  }
  const binary2 = atob(encoded);
  const bytes = new Uint8Array(binary2.length);
  for (let i = 0; i < binary2.length; i++) {
    bytes[i] = binary2.charCodeAt(i);
  }
  return bytes;
}
__name(decodeBase64, "decodeBase64");

// node_modules/jose/dist/webapi/util/base64url.js
function decode2(input) {
  if (Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(typeof input === "string" ? input : decoder.decode(input), {
      alphabet: "base64url"
    });
  }
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder.decode(encoded);
  }
  encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  try {
    return decodeBase64(encoded);
  } catch {
    throw new TypeError("The input to be decoded is not correctly encoded.");
  }
}
__name(decode2, "decode");
function encode2(input) {
  let unencoded = input;
  if (typeof unencoded === "string") {
    unencoded = encoder2.encode(unencoded);
  }
  if (Uint8Array.prototype.toBase64) {
    return unencoded.toBase64({
      alphabet: "base64url",
      omitPadding: true
    });
  }
  return encodeBase64(unencoded).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
__name(encode2, "encode");

// node_modules/jose/dist/webapi/util/errors.js
var JOSEError = class extends Error {
  static {
    __name(this, "JOSEError");
  }
  static code = "ERR_JOSE_GENERIC";
  code = "ERR_JOSE_GENERIC";
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var JWTClaimValidationFailed = class extends JOSEError {
  static {
    __name(this, "JWTClaimValidationFailed");
  }
  static code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, {
      cause: {
        claim,
        reason,
        payload
      }
    });
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JWTExpired = class extends JOSEError {
  static {
    __name(this, "JWTExpired");
  }
  static code = "ERR_JWT_EXPIRED";
  code = "ERR_JWT_EXPIRED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, {
      cause: {
        claim,
        reason,
        payload
      }
    });
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JOSEAlgNotAllowed = class extends JOSEError {
  static {
    __name(this, "JOSEAlgNotAllowed");
  }
  static code = "ERR_JOSE_ALG_NOT_ALLOWED";
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
};
var JOSENotSupported = class extends JOSEError {
  static {
    __name(this, "JOSENotSupported");
  }
  static code = "ERR_JOSE_NOT_SUPPORTED";
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWSInvalid = class extends JOSEError {
  static {
    __name(this, "JWSInvalid");
  }
  static code = "ERR_JWS_INVALID";
  code = "ERR_JWS_INVALID";
};
var JWTInvalid = class extends JOSEError {
  static {
    __name(this, "JWTInvalid");
  }
  static code = "ERR_JWT_INVALID";
  code = "ERR_JWT_INVALID";
};
var JWKSInvalid = class extends JOSEError {
  static {
    __name(this, "JWKSInvalid");
  }
  static code = "ERR_JWKS_INVALID";
  code = "ERR_JWKS_INVALID";
};
var JWKSNoMatchingKey = class extends JOSEError {
  static {
    __name(this, "JWKSNoMatchingKey");
  }
  static code = "ERR_JWKS_NO_MATCHING_KEY";
  code = "ERR_JWKS_NO_MATCHING_KEY";
  constructor(message2 = "no applicable key found in the JSON Web Key Set", options) {
    super(message2, options);
  }
};
var JWKSMultipleMatchingKeys = class extends JOSEError {
  static {
    __name(this, "JWKSMultipleMatchingKeys");
  }
  [Symbol.asyncIterator];
  static code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  constructor(message2 = "multiple matching keys found in the JSON Web Key Set", options) {
    super(message2, options);
  }
};
var JWKSTimeout = class extends JOSEError {
  static {
    __name(this, "JWKSTimeout");
  }
  static code = "ERR_JWKS_TIMEOUT";
  code = "ERR_JWKS_TIMEOUT";
  constructor(message2 = "request timed out", options) {
    super(message2, options);
  }
};
var JWSSignatureVerificationFailed = class extends JOSEError {
  static {
    __name(this, "JWSSignatureVerificationFailed");
  }
  static code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  constructor(message2 = "signature verification failed", options) {
    super(message2, options);
  }
};

// node_modules/jose/dist/webapi/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
__name(unusable, "unusable");
function isAlgorithm(algorithm2, name) {
  return algorithm2.name === name;
}
__name(isAlgorithm, "isAlgorithm");
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
__name(getHashLength, "getHashLength");
function getNamedCurve(alg) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
__name(getNamedCurve, "getNamedCurve");
function checkUsage(key, usage) {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
  }
}
__name(checkUsage, "checkUsage");
function checkSigCryptoKey(key, alg, usage) {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC")) throw unusable("HMAC");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5")) throw unusable("RSASSA-PKCS1-v1_5");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS")) throw unusable("RSA-PSS");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "Ed25519":
    case "EdDSA": {
      if (!isAlgorithm(key.algorithm, "Ed25519")) throw unusable("Ed25519");
      break;
    }
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87": {
      if (!isAlgorithm(key.algorithm, alg)) throw unusable(alg);
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA")) throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected) throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usage);
}
__name(checkSigCryptoKey, "checkSigCryptoKey");

// node_modules/jose/dist/webapi/lib/invalid_key_input.js
function message(msg, actual, ...types) {
  types = types.filter(Boolean);
  if (types.length > 2) {
    const last = types.pop();
    msg += `one of type ${types.join(", ")}, or ${last}.`;
  } else if (types.length === 2) {
    msg += `one of type ${types[0]} or ${types[1]}.`;
  } else {
    msg += `of type ${types[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
__name(message, "message");
var invalid_key_input_default = /* @__PURE__ */ __name(((actual, ...types) => {
  return message("Key must be ", actual, ...types);
}), "default");
function withAlg(alg, actual, ...types) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types);
}
__name(withAlg, "withAlg");

// node_modules/jose/dist/webapi/lib/is_key_like.js
function isCryptoKey(key) {
  return key?.[Symbol.toStringTag] === "CryptoKey";
}
__name(isCryptoKey, "isCryptoKey");
function isKeyObject(key) {
  return key?.[Symbol.toStringTag] === "KeyObject";
}
__name(isKeyObject, "isKeyObject");
var is_key_like_default = /* @__PURE__ */ __name(((key) => {
  return isCryptoKey(key) || isKeyObject(key);
}), "default");

// node_modules/jose/dist/webapi/lib/is_disjoint.js
var is_disjoint_default = /* @__PURE__ */ __name(((...headers) => {
  const sources = headers.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
}), "default");

// node_modules/jose/dist/webapi/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
__name(isObjectLike, "isObjectLike");
var is_object_default = /* @__PURE__ */ __name(((input) => {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}), "default");

// node_modules/jose/dist/webapi/lib/check_key_length.js
var check_key_length_default = /* @__PURE__ */ __name(((alg, key) => {
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
    }
  }
}), "default");

// node_modules/jose/dist/webapi/lib/jwk_to_key.js
function subtleMapping(jwk) {
  let algorithm2;
  let keyUsages;
  switch (jwk.kty) {
    case "AKP": {
      switch (jwk.alg) {
        case "ML-DSA-44":
        case "ML-DSA-65":
        case "ML-DSA-87":
          algorithm2 = {
            name: jwk.alg
          };
          keyUsages = jwk.priv ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm2 = {
            name: "RSA-PSS",
            hash: `SHA-${jwk.alg.slice(-3)}`
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm2 = {
            name: "RSASSA-PKCS1-v1_5",
            hash: `SHA-${jwk.alg.slice(-3)}`
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm2 = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? [
            "decrypt",
            "unwrapKey"
          ] : [
            "encrypt",
            "wrapKey"
          ];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm2 = {
            name: "ECDSA",
            namedCurve: "P-256"
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "ES384":
          algorithm2 = {
            name: "ECDSA",
            namedCurve: "P-384"
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "ES512":
          algorithm2 = {
            name: "ECDSA",
            namedCurve: "P-521"
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm2 = {
            name: "ECDH",
            namedCurve: jwk.crv
          };
          keyUsages = jwk.d ? [
            "deriveBits"
          ] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
        case "EdDSA":
          algorithm2 = {
            name: "Ed25519"
          };
          keyUsages = jwk.d ? [
            "sign"
          ] : [
            "verify"
          ];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm2 = {
            name: jwk.crv
          };
          keyUsages = jwk.d ? [
            "deriveBits"
          ] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return {
    algorithm: algorithm2,
    keyUsages
  };
}
__name(subtleMapping, "subtleMapping");
var jwk_to_key_default = /* @__PURE__ */ __name((async (jwk) => {
  if (!jwk.alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  }
  const { algorithm: algorithm2, keyUsages } = subtleMapping(jwk);
  const keyData = {
    ...jwk
  };
  if (keyData.kty !== "AKP") {
    delete keyData.alg;
  }
  delete keyData.use;
  return crypto.subtle.importKey("jwk", keyData, algorithm2, jwk.ext ?? (jwk.d || jwk.priv ? false : true), jwk.key_ops ?? keyUsages);
}), "default");

// node_modules/jose/dist/webapi/key/import.js
async function importJWK(jwk, alg, options) {
  if (!is_object_default(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  let ext;
  alg ??= jwk.alg;
  ext ??= options?.extractable ?? jwk.ext;
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode2(jwk.k);
    case "RSA":
      if ("oth" in jwk && jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
      return jwk_to_key_default({
        ...jwk,
        alg,
        ext
      });
    case "AKP": {
      if (typeof jwk.alg !== "string" || !jwk.alg) {
        throw new TypeError('missing "alg" (Algorithm) Parameter value');
      }
      if (alg !== void 0 && alg !== jwk.alg) {
        throw new TypeError("JWK alg and alg option value mismatch");
      }
      return jwk_to_key_default({
        ...jwk,
        ext
      });
    }
    case "EC":
    case "OKP":
      return jwk_to_key_default({
        ...jwk,
        alg,
        ext
      });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
__name(importJWK, "importJWK");

// node_modules/jose/dist/webapi/lib/validate_crit.js
var validate_crit_default = /* @__PURE__ */ __name(((Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) => {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([
      ...Object.entries(recognizedOption),
      ...recognizedDefault.entries()
    ]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}), "default");

// node_modules/jose/dist/webapi/lib/validate_algorithms.js
var validate_algorithms_default = /* @__PURE__ */ __name(((option, algorithms) => {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s2) => typeof s2 !== "string"))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }
  if (!algorithms) {
    return void 0;
  }
  return new Set(algorithms);
}), "default");

// node_modules/jose/dist/webapi/lib/is_jwk.js
function isJWK(key) {
  return is_object_default(key) && typeof key.kty === "string";
}
__name(isJWK, "isJWK");
function isPrivateJWK(key) {
  return key.kty !== "oct" && (key.kty === "AKP" && typeof key.priv === "string" || typeof key.d === "string");
}
__name(isPrivateJWK, "isPrivateJWK");
function isPublicJWK(key) {
  return key.kty !== "oct" && typeof key.d === "undefined" && typeof key.priv === "undefined";
}
__name(isPublicJWK, "isPublicJWK");
function isSecretJWK(key) {
  return key.kty === "oct" && typeof key.k === "string";
}
__name(isSecretJWK, "isSecretJWK");

// node_modules/jose/dist/webapi/lib/normalize_key.js
var cache;
var handleJWK = /* @__PURE__ */ __name(async (key, jwk, alg, freeze = false) => {
  cache ||= /* @__PURE__ */ new WeakMap();
  let cached3 = cache.get(key);
  if (cached3?.[alg]) {
    return cached3[alg];
  }
  const cryptoKey = await jwk_to_key_default({
    ...jwk,
    alg
  });
  if (freeze) Object.freeze(key);
  if (!cached3) {
    cache.set(key, {
      [alg]: cryptoKey
    });
  } else {
    cached3[alg] = cryptoKey;
  }
  return cryptoKey;
}, "handleJWK");
var handleKeyObject = /* @__PURE__ */ __name((keyObject, alg) => {
  cache ||= /* @__PURE__ */ new WeakMap();
  let cached3 = cache.get(keyObject);
  if (cached3?.[alg]) {
    return cached3[alg];
  }
  const isPublic = keyObject.type === "public";
  const extractable = isPublic ? true : false;
  let cryptoKey;
  if (keyObject.asymmetricKeyType === "x25519") {
    switch (alg) {
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW":
        break;
      default:
        throw new TypeError("given KeyObject instance cannot be used for this algorithm");
    }
    cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, isPublic ? [] : [
      "deriveBits"
    ]);
  }
  if (keyObject.asymmetricKeyType === "ed25519") {
    if (alg !== "EdDSA" && alg !== "Ed25519") {
      throw new TypeError("given KeyObject instance cannot be used for this algorithm");
    }
    cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [
      isPublic ? "verify" : "sign"
    ]);
  }
  switch (keyObject.asymmetricKeyType) {
    case "ml-dsa-44":
    case "ml-dsa-65":
    case "ml-dsa-87": {
      if (alg !== keyObject.asymmetricKeyType.toUpperCase()) {
        throw new TypeError("given KeyObject instance cannot be used for this algorithm");
      }
      cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [
        isPublic ? "verify" : "sign"
      ]);
    }
  }
  if (keyObject.asymmetricKeyType === "rsa") {
    let hash;
    switch (alg) {
      case "RSA-OAEP":
        hash = "SHA-1";
        break;
      case "RS256":
      case "PS256":
      case "RSA-OAEP-256":
        hash = "SHA-256";
        break;
      case "RS384":
      case "PS384":
      case "RSA-OAEP-384":
        hash = "SHA-384";
        break;
      case "RS512":
      case "PS512":
      case "RSA-OAEP-512":
        hash = "SHA-512";
        break;
      default:
        throw new TypeError("given KeyObject instance cannot be used for this algorithm");
    }
    if (alg.startsWith("RSA-OAEP")) {
      return keyObject.toCryptoKey({
        name: "RSA-OAEP",
        hash
      }, extractable, isPublic ? [
        "encrypt"
      ] : [
        "decrypt"
      ]);
    }
    cryptoKey = keyObject.toCryptoKey({
      name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
      hash
    }, extractable, [
      isPublic ? "verify" : "sign"
    ]);
  }
  if (keyObject.asymmetricKeyType === "ec") {
    const nist = /* @__PURE__ */ new Map([
      [
        "prime256v1",
        "P-256"
      ],
      [
        "secp384r1",
        "P-384"
      ],
      [
        "secp521r1",
        "P-521"
      ]
    ]);
    const namedCurve = nist.get(keyObject.asymmetricKeyDetails?.namedCurve);
    if (!namedCurve) {
      throw new TypeError("given KeyObject instance cannot be used for this algorithm");
    }
    if (alg === "ES256" && namedCurve === "P-256") {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDSA",
        namedCurve
      }, extractable, [
        isPublic ? "verify" : "sign"
      ]);
    }
    if (alg === "ES384" && namedCurve === "P-384") {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDSA",
        namedCurve
      }, extractable, [
        isPublic ? "verify" : "sign"
      ]);
    }
    if (alg === "ES512" && namedCurve === "P-521") {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDSA",
        namedCurve
      }, extractable, [
        isPublic ? "verify" : "sign"
      ]);
    }
    if (alg.startsWith("ECDH-ES")) {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDH",
        namedCurve
      }, extractable, isPublic ? [] : [
        "deriveBits"
      ]);
    }
  }
  if (!cryptoKey) {
    throw new TypeError("given KeyObject instance cannot be used for this algorithm");
  }
  if (!cached3) {
    cache.set(keyObject, {
      [alg]: cryptoKey
    });
  } else {
    cached3[alg] = cryptoKey;
  }
  return cryptoKey;
}, "handleKeyObject");
var normalize_key_default = /* @__PURE__ */ __name((async (key, alg) => {
  if (key instanceof Uint8Array) {
    return key;
  }
  if (isCryptoKey(key)) {
    return key;
  }
  if (isKeyObject(key)) {
    if (key.type === "secret") {
      return key.export();
    }
    if ("toCryptoKey" in key && typeof key.toCryptoKey === "function") {
      try {
        return handleKeyObject(key, alg);
      } catch (err) {
        if (err instanceof TypeError) {
          throw err;
        }
      }
    }
    let jwk = key.export({
      format: "jwk"
    });
    return handleJWK(key, jwk, alg);
  }
  if (isJWK(key)) {
    if (key.k) {
      return decode2(key.k);
    }
    return handleJWK(key, key, alg, true);
  }
  throw new Error("unreachable");
}), "default");

// node_modules/jose/dist/webapi/lib/check_key_type.js
var tag = /* @__PURE__ */ __name((key) => key?.[Symbol.toStringTag], "tag");
var jwkMatchesOp = /* @__PURE__ */ __name((alg, key, usage) => {
  if (key.use !== void 0) {
    let expected;
    switch (usage) {
      case "sign":
      case "verify":
        expected = "sig";
        break;
      case "encrypt":
      case "decrypt":
        expected = "enc";
        break;
    }
    if (key.use !== expected) {
      throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
    }
  }
  if (key.alg !== void 0 && key.alg !== alg) {
    throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
  }
  if (Array.isArray(key.key_ops)) {
    let expectedKeyOp;
    switch (true) {
      case (usage === "sign" || usage === "verify"):
      case alg === "dir":
      case alg.includes("CBC-HS"):
        expectedKeyOp = usage;
        break;
      case alg.startsWith("PBES2"):
        expectedKeyOp = "deriveBits";
        break;
      case /^A\d{3}(?:GCM)?(?:KW)?$/.test(alg):
        if (!alg.includes("GCM") && alg.endsWith("KW")) {
          expectedKeyOp = usage === "encrypt" ? "wrapKey" : "unwrapKey";
        } else {
          expectedKeyOp = usage;
        }
        break;
      case (usage === "encrypt" && alg.startsWith("RSA")):
        expectedKeyOp = "wrapKey";
        break;
      case usage === "decrypt":
        expectedKeyOp = alg.startsWith("RSA") ? "unwrapKey" : "deriveBits";
        break;
    }
    if (expectedKeyOp && key.key_ops?.includes?.(expectedKeyOp) === false) {
      throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
    }
  }
  return true;
}, "jwkMatchesOp");
var symmetricTypeCheck = /* @__PURE__ */ __name((alg, key, usage) => {
  if (key instanceof Uint8Array) return;
  if (isJWK(key)) {
    if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage)) return;
    throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
  }
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key", "Uint8Array"));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
  }
}, "symmetricTypeCheck");
var asymmetricTypeCheck = /* @__PURE__ */ __name((alg, key, usage) => {
  if (isJWK(key)) {
    switch (usage) {
      case "decrypt":
      case "sign":
        if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage)) return;
        throw new TypeError(`JSON Web Key for this operation be a private JWK`);
      case "encrypt":
      case "verify":
        if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage)) return;
        throw new TypeError(`JSON Web Key for this operation be a public JWK`);
    }
  }
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key"));
  }
  if (key.type === "secret") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (key.type === "public") {
    switch (usage) {
      case "sign":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
      case "decrypt":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
      default:
        break;
    }
  }
  if (key.type === "private") {
    switch (usage) {
      case "verify":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
      case "encrypt":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
      default:
        break;
    }
  }
}, "asymmetricTypeCheck");
var check_key_type_default = /* @__PURE__ */ __name(((alg, key, usage) => {
  const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A(?:128|192|256)(?:GCM)?(?:KW)?$/.test(alg) || /^A(?:128|192|256)CBC-HS(?:256|384|512)$/.test(alg);
  if (symmetric) {
    symmetricTypeCheck(alg, key, usage);
  } else {
    asymmetricTypeCheck(alg, key, usage);
  }
}), "default");

// node_modules/jose/dist/webapi/lib/subtle_dsa.js
var subtle_dsa_default = /* @__PURE__ */ __name(((alg, algorithm2) => {
  const hash = `SHA-${alg.slice(-3)}`;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
      return {
        hash,
        name: "HMAC"
      };
    case "PS256":
    case "PS384":
    case "PS512":
      return {
        hash,
        name: "RSA-PSS",
        saltLength: parseInt(alg.slice(-3), 10) >> 3
      };
    case "RS256":
    case "RS384":
    case "RS512":
      return {
        hash,
        name: "RSASSA-PKCS1-v1_5"
      };
    case "ES256":
    case "ES384":
    case "ES512":
      return {
        hash,
        name: "ECDSA",
        namedCurve: algorithm2.namedCurve
      };
    case "Ed25519":
    case "EdDSA":
      return {
        name: "Ed25519"
      };
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87":
      return {
        name: alg
      };
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}), "default");

// node_modules/jose/dist/webapi/lib/get_sign_verify_key.js
var get_sign_verify_key_default = /* @__PURE__ */ __name((async (alg, key, usage) => {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(invalid_key_input_default(key, "CryptoKey", "KeyObject", "JSON Web Key"));
    }
    return crypto.subtle.importKey("raw", key, {
      hash: `SHA-${alg.slice(-3)}`,
      name: "HMAC"
    }, false, [
      usage
    ]);
  }
  checkSigCryptoKey(key, alg, usage);
  return key;
}), "default");

// node_modules/jose/dist/webapi/lib/verify.js
var verify_default = /* @__PURE__ */ __name((async (alg, key, signature, data) => {
  const cryptoKey = await get_sign_verify_key_default(alg, key, "verify");
  check_key_length_default(alg, cryptoKey);
  const algorithm2 = subtle_dsa_default(alg, cryptoKey.algorithm);
  try {
    return await crypto.subtle.verify(algorithm2, cryptoKey, signature, data);
  } catch {
    return false;
  }
}), "default");

// node_modules/jose/dist/webapi/jws/flattened/verify.js
async function flattenedVerify(jws, key, options) {
  if (!is_object_default(jws)) {
    throw new JWSInvalid("Flattened JWS must be an object");
  }
  if (jws.protected === void 0 && jws.header === void 0) {
    throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
  }
  if (jws.protected !== void 0 && typeof jws.protected !== "string") {
    throw new JWSInvalid("JWS Protected Header incorrect type");
  }
  if (jws.payload === void 0) {
    throw new JWSInvalid("JWS Payload missing");
  }
  if (typeof jws.signature !== "string") {
    throw new JWSInvalid("JWS Signature missing or incorrect type");
  }
  if (jws.header !== void 0 && !is_object_default(jws.header)) {
    throw new JWSInvalid("JWS Unprotected Header incorrect type");
  }
  let parsedProt = {};
  if (jws.protected) {
    try {
      const protectedHeader = decode2(jws.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader));
    } catch {
      throw new JWSInvalid("JWS Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jws.header)) {
    throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jws.header
  };
  const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([
    [
      "b64",
      true
    ]
  ]), options?.crit, parsedProt, joseHeader);
  let b64 = true;
  if (extensions.has("b64")) {
    b64 = parsedProt.b64;
    if (typeof b64 !== "boolean") {
      throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    }
  }
  const { alg } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }
  const algorithms = options && validate_algorithms_default("algorithms", options.algorithms);
  if (algorithms && !algorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (b64) {
    if (typeof jws.payload !== "string") {
      throw new JWSInvalid("JWS Payload must be a string");
    }
  } else if (typeof jws.payload !== "string" && !(jws.payload instanceof Uint8Array)) {
    throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jws);
    resolvedKey = true;
  }
  check_key_type_default(alg, key, "verify");
  const data = concat(encoder2.encode(jws.protected ?? ""), encoder2.encode("."), typeof jws.payload === "string" ? encoder2.encode(jws.payload) : jws.payload);
  let signature;
  try {
    signature = decode2(jws.signature);
  } catch {
    throw new JWSInvalid("Failed to base64url decode the signature");
  }
  const k = await normalize_key_default(key, alg);
  const verified = await verify_default(alg, k, signature, data);
  if (!verified) {
    throw new JWSSignatureVerificationFailed();
  }
  let payload;
  if (b64) {
    try {
      payload = decode2(jws.payload);
    } catch {
      throw new JWSInvalid("Failed to base64url decode the payload");
    }
  } else if (typeof jws.payload === "string") {
    payload = encoder2.encode(jws.payload);
  } else {
    payload = jws.payload;
  }
  const result = {
    payload
  };
  if (jws.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jws.header !== void 0) {
    result.unprotectedHeader = jws.header;
  }
  if (resolvedKey) {
    return {
      ...result,
      key: k
    };
  }
  return result;
}
__name(flattenedVerify, "flattenedVerify");

// node_modules/jose/dist/webapi/jws/compact/verify.js
async function compactVerify(jws, key, options) {
  if (jws instanceof Uint8Array) {
    jws = decoder.decode(jws);
  }
  if (typeof jws !== "string") {
    throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split(".");
  if (length !== 3) {
    throw new JWSInvalid("Invalid Compact JWS");
  }
  const verified = await flattenedVerify({
    payload,
    protected: protectedHeader,
    signature
  }, key, options);
  const result = {
    payload: verified.payload,
    protectedHeader: verified.protectedHeader
  };
  if (typeof key === "function") {
    return {
      ...result,
      key: verified.key
    };
  }
  return result;
}
__name(compactVerify, "compactVerify");

// node_modules/jose/dist/webapi/lib/epoch.js
var epoch_default = /* @__PURE__ */ __name(((date5) => Math.floor(date5.getTime() / 1e3)), "default");

// node_modules/jose/dist/webapi/lib/secs.js
var minute = 60;
var hour = minute * 60;
var day = hour * 24;
var week = day * 7;
var year = day * 365.25;
var REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
var secs_default = /* @__PURE__ */ __name(((str) => {
  const matched = REGEX.exec(str);
  if (!matched || matched[4] && matched[1]) {
    throw new TypeError("Invalid time period format");
  }
  const value = parseFloat(matched[2]);
  const unit = matched[3].toLowerCase();
  let numericDate;
  switch (unit) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
      numericDate = Math.round(value);
      break;
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
      numericDate = Math.round(value * minute);
      break;
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
      numericDate = Math.round(value * hour);
      break;
    case "day":
    case "days":
    case "d":
      numericDate = Math.round(value * day);
      break;
    case "week":
    case "weeks":
    case "w":
      numericDate = Math.round(value * week);
      break;
    default:
      numericDate = Math.round(value * year);
      break;
  }
  if (matched[1] === "-" || matched[4] === "ago") {
    return -numericDate;
  }
  return numericDate;
}), "default");

// node_modules/jose/dist/webapi/lib/jwt_claims_set.js
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
__name(validateInput, "validateInput");
var normalizeTyp = /* @__PURE__ */ __name((value) => {
  if (value.includes("/")) {
    return value.toLowerCase();
  }
  return `application/${value.toLowerCase()}`;
}, "normalizeTyp");
var checkAudiencePresence = /* @__PURE__ */ __name((audPayload, audOption) => {
  if (typeof audPayload === "string") {
    return audOption.includes(audPayload);
  }
  if (Array.isArray(audPayload)) {
    return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
  }
  return false;
}, "checkAudiencePresence");
function validateClaimsSet(protectedHeader, encodedPayload, options = {}) {
  let payload;
  try {
    payload = JSON.parse(decoder.decode(encodedPayload));
  } catch {
  }
  if (!is_object_default(payload)) {
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
  }
  const { typ } = options;
  if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
    throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, "typ", "check_failed");
  }
  const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
  const presenceCheck = [
    ...requiredClaims
  ];
  if (maxTokenAge !== void 0) presenceCheck.push("iat");
  if (audience !== void 0) presenceCheck.push("aud");
  if (subject !== void 0) presenceCheck.push("sub");
  if (issuer !== void 0) presenceCheck.push("iss");
  for (const claim of new Set(presenceCheck.reverse())) {
    if (!(claim in payload)) {
      throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, "missing");
    }
  }
  if (issuer && !(Array.isArray(issuer) ? issuer : [
    issuer
  ]).includes(payload.iss)) {
    throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, "iss", "check_failed");
  }
  if (subject && payload.sub !== subject) {
    throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, "sub", "check_failed");
  }
  if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [
    audience
  ] : audience)) {
    throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, "aud", "check_failed");
  }
  let tolerance;
  switch (typeof options.clockTolerance) {
    case "string":
      tolerance = secs_default(options.clockTolerance);
      break;
    case "number":
      tolerance = options.clockTolerance;
      break;
    case "undefined":
      tolerance = 0;
      break;
    default:
      throw new TypeError("Invalid clockTolerance option type");
  }
  const { currentDate } = options;
  const now = epoch_default(currentDate || /* @__PURE__ */ new Date());
  if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
    throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, "iat", "invalid");
  }
  if (payload.nbf !== void 0) {
    if (typeof payload.nbf !== "number") {
      throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, "nbf", "invalid");
    }
    if (payload.nbf > now + tolerance) {
      throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, "nbf", "check_failed");
    }
  }
  if (payload.exp !== void 0) {
    if (typeof payload.exp !== "number") {
      throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, "exp", "invalid");
    }
    if (payload.exp <= now - tolerance) {
      throw new JWTExpired('"exp" claim timestamp check failed', payload, "exp", "check_failed");
    }
  }
  if (maxTokenAge) {
    const age = now - payload.iat;
    const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
    if (age - tolerance > max) {
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, "iat", "check_failed");
    }
    if (age < 0 - tolerance) {
      throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, "iat", "check_failed");
    }
  }
  return payload;
}
__name(validateClaimsSet, "validateClaimsSet");
var JWTClaimsBuilder = class {
  static {
    __name(this, "JWTClaimsBuilder");
  }
  #payload;
  constructor(payload) {
    if (!is_object_default(payload)) {
      throw new TypeError("JWT Claims Set MUST be an object");
    }
    this.#payload = structuredClone(payload);
  }
  data() {
    return encoder2.encode(JSON.stringify(this.#payload));
  }
  get iss() {
    return this.#payload.iss;
  }
  set iss(value) {
    this.#payload.iss = value;
  }
  get sub() {
    return this.#payload.sub;
  }
  set sub(value) {
    this.#payload.sub = value;
  }
  get aud() {
    return this.#payload.aud;
  }
  set aud(value) {
    this.#payload.aud = value;
  }
  set jti(value) {
    this.#payload.jti = value;
  }
  set nbf(value) {
    if (typeof value === "number") {
      this.#payload.nbf = validateInput("setNotBefore", value);
    } else if (value instanceof Date) {
      this.#payload.nbf = validateInput("setNotBefore", epoch_default(value));
    } else {
      this.#payload.nbf = epoch_default(/* @__PURE__ */ new Date()) + secs_default(value);
    }
  }
  set exp(value) {
    if (typeof value === "number") {
      this.#payload.exp = validateInput("setExpirationTime", value);
    } else if (value instanceof Date) {
      this.#payload.exp = validateInput("setExpirationTime", epoch_default(value));
    } else {
      this.#payload.exp = epoch_default(/* @__PURE__ */ new Date()) + secs_default(value);
    }
  }
  set iat(value) {
    if (typeof value === "undefined") {
      this.#payload.iat = epoch_default(/* @__PURE__ */ new Date());
    } else if (value instanceof Date) {
      this.#payload.iat = validateInput("setIssuedAt", epoch_default(value));
    } else if (typeof value === "string") {
      this.#payload.iat = validateInput("setIssuedAt", epoch_default(/* @__PURE__ */ new Date()) + secs_default(value));
    } else {
      this.#payload.iat = validateInput("setIssuedAt", value);
    }
  }
};

// node_modules/jose/dist/webapi/jwt/verify.js
async function jwtVerify(jwt2, key, options) {
  const verified = await compactVerify(jwt2, key, options);
  if (verified.protectedHeader.crit?.includes("b64") && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
  }
  const payload = validateClaimsSet(verified.protectedHeader, verified.payload, options);
  const result = {
    payload,
    protectedHeader: verified.protectedHeader
  };
  if (typeof key === "function") {
    return {
      ...result,
      key: verified.key
    };
  }
  return result;
}
__name(jwtVerify, "jwtVerify");

// node_modules/jose/dist/webapi/lib/sign.js
var sign_default = /* @__PURE__ */ __name((async (alg, key, data) => {
  const cryptoKey = await get_sign_verify_key_default(alg, key, "sign");
  check_key_length_default(alg, cryptoKey);
  const signature = await crypto.subtle.sign(subtle_dsa_default(alg, cryptoKey.algorithm), cryptoKey, data);
  return new Uint8Array(signature);
}), "default");

// node_modules/jose/dist/webapi/jws/flattened/sign.js
var FlattenedSign = class {
  static {
    __name(this, "FlattenedSign");
  }
  #payload;
  #protectedHeader;
  #unprotectedHeader;
  constructor(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError("payload must be an instance of Uint8Array");
    }
    this.#payload = payload;
  }
  setProtectedHeader(protectedHeader) {
    if (this.#protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this.#protectedHeader = protectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this.#unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this.#unprotectedHeader = unprotectedHeader;
    return this;
  }
  async sign(key, options) {
    if (!this.#protectedHeader && !this.#unprotectedHeader) {
      throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
    }
    if (!is_disjoint_default(this.#protectedHeader, this.#unprotectedHeader)) {
      throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
    }
    const joseHeader = {
      ...this.#protectedHeader,
      ...this.#unprotectedHeader
    };
    const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([
      [
        "b64",
        true
      ]
    ]), options?.crit, this.#protectedHeader, joseHeader);
    let b64 = true;
    if (extensions.has("b64")) {
      b64 = this.#protectedHeader.b64;
      if (typeof b64 !== "boolean") {
        throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
      }
    }
    const { alg } = joseHeader;
    if (typeof alg !== "string" || !alg) {
      throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    check_key_type_default(alg, key, "sign");
    let payload = this.#payload;
    if (b64) {
      payload = encoder2.encode(encode2(payload));
    }
    let protectedHeader;
    if (this.#protectedHeader) {
      protectedHeader = encoder2.encode(encode2(JSON.stringify(this.#protectedHeader)));
    } else {
      protectedHeader = encoder2.encode("");
    }
    const data = concat(protectedHeader, encoder2.encode("."), payload);
    const k = await normalize_key_default(key, alg);
    const signature = await sign_default(alg, k, data);
    const jws = {
      signature: encode2(signature),
      payload: ""
    };
    if (b64) {
      jws.payload = decoder.decode(payload);
    }
    if (this.#unprotectedHeader) {
      jws.header = this.#unprotectedHeader;
    }
    if (this.#protectedHeader) {
      jws.protected = decoder.decode(protectedHeader);
    }
    return jws;
  }
};

// node_modules/jose/dist/webapi/jws/compact/sign.js
var CompactSign = class {
  static {
    __name(this, "CompactSign");
  }
  #flattened;
  constructor(payload) {
    this.#flattened = new FlattenedSign(payload);
  }
  setProtectedHeader(protectedHeader) {
    this.#flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  async sign(key, options) {
    const jws = await this.#flattened.sign(key, options);
    if (jws.payload === void 0) {
      throw new TypeError("use the flattened module for creating JWS with b64: false");
    }
    return `${jws.protected}.${jws.payload}.${jws.signature}`;
  }
};

// node_modules/jose/dist/webapi/jwt/sign.js
var SignJWT = class {
  static {
    __name(this, "SignJWT");
  }
  #protectedHeader;
  #jwt;
  constructor(payload = {}) {
    this.#jwt = new JWTClaimsBuilder(payload);
  }
  setIssuer(issuer) {
    this.#jwt.iss = issuer;
    return this;
  }
  setSubject(subject) {
    this.#jwt.sub = subject;
    return this;
  }
  setAudience(audience) {
    this.#jwt.aud = audience;
    return this;
  }
  setJti(jwtId) {
    this.#jwt.jti = jwtId;
    return this;
  }
  setNotBefore(input) {
    this.#jwt.nbf = input;
    return this;
  }
  setExpirationTime(input) {
    this.#jwt.exp = input;
    return this;
  }
  setIssuedAt(input) {
    this.#jwt.iat = input;
    return this;
  }
  setProtectedHeader(protectedHeader) {
    this.#protectedHeader = protectedHeader;
    return this;
  }
  async sign(key, options) {
    const sig = new CompactSign(this.#jwt.data());
    sig.setProtectedHeader(this.#protectedHeader);
    if (Array.isArray(this.#protectedHeader?.crit) && this.#protectedHeader.crit.includes("b64") && this.#protectedHeader.b64 === false) {
      throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
    }
    return sig.sign(key, options);
  }
};

// node_modules/jose/dist/webapi/jwks/local.js
function getKtyFromAlg(alg) {
  switch (typeof alg === "string" && alg.slice(0, 2)) {
    case "RS":
    case "PS":
      return "RSA";
    case "ES":
      return "EC";
    case "Ed":
      return "OKP";
    case "ML":
      return "AKP";
    default:
      throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
  }
}
__name(getKtyFromAlg, "getKtyFromAlg");
function isJWKSLike(jwks) {
  return jwks && typeof jwks === "object" && Array.isArray(jwks.keys) && jwks.keys.every(isJWKLike);
}
__name(isJWKSLike, "isJWKSLike");
function isJWKLike(key) {
  return is_object_default(key);
}
__name(isJWKLike, "isJWKLike");
var LocalJWKSet = class LocalJWKSet2 {
  static {
    __name(this, "LocalJWKSet");
  }
  #jwks;
  #cached = /* @__PURE__ */ new WeakMap();
  constructor(jwks) {
    if (!isJWKSLike(jwks)) {
      throw new JWKSInvalid("JSON Web Key Set malformed");
    }
    this.#jwks = structuredClone(jwks);
  }
  jwks() {
    return this.#jwks;
  }
  async getKey(protectedHeader, token) {
    const { alg, kid } = {
      ...protectedHeader,
      ...token?.header
    };
    const kty = getKtyFromAlg(alg);
    const candidates = this.#jwks.keys.filter((jwk2) => {
      let candidate = kty === jwk2.kty;
      if (candidate && typeof kid === "string") {
        candidate = kid === jwk2.kid;
      }
      if (candidate && (typeof jwk2.alg === "string" || kty === "AKP")) {
        candidate = alg === jwk2.alg;
      }
      if (candidate && typeof jwk2.use === "string") {
        candidate = jwk2.use === "sig";
      }
      if (candidate && Array.isArray(jwk2.key_ops)) {
        candidate = jwk2.key_ops.includes("verify");
      }
      if (candidate) {
        switch (alg) {
          case "ES256":
            candidate = jwk2.crv === "P-256";
            break;
          case "ES384":
            candidate = jwk2.crv === "P-384";
            break;
          case "ES512":
            candidate = jwk2.crv === "P-521";
            break;
          case "Ed25519":
          case "EdDSA":
            candidate = jwk2.crv === "Ed25519";
            break;
        }
      }
      return candidate;
    });
    const { 0: jwk, length } = candidates;
    if (length === 0) {
      throw new JWKSNoMatchingKey();
    }
    if (length !== 1) {
      const error3 = new JWKSMultipleMatchingKeys();
      const _cached = this.#cached;
      error3[Symbol.asyncIterator] = async function* () {
        for (const jwk2 of candidates) {
          try {
            yield await importWithAlgCache(_cached, jwk2, alg);
          } catch {
          }
        }
      };
      throw error3;
    }
    return importWithAlgCache(this.#cached, jwk, alg);
  }
};
async function importWithAlgCache(cache2, jwk, alg) {
  const cached3 = cache2.get(jwk) || cache2.set(jwk, {}).get(jwk);
  if (cached3[alg] === void 0) {
    const key = await importJWK({
      ...jwk,
      ext: true
    }, alg);
    if (key instanceof Uint8Array || key.type !== "public") {
      throw new JWKSInvalid("JSON Web Key Set members must be public keys");
    }
    cached3[alg] = key;
  }
  return cached3[alg];
}
__name(importWithAlgCache, "importWithAlgCache");
function createLocalJWKSet(jwks) {
  const set = new LocalJWKSet(jwks);
  const localJWKSet = /* @__PURE__ */ __name(async (protectedHeader, token) => set.getKey(protectedHeader, token), "localJWKSet");
  Object.defineProperties(localJWKSet, {
    jwks: {
      value: /* @__PURE__ */ __name(() => structuredClone(set.jwks()), "value"),
      enumerable: false,
      configurable: false,
      writable: false
    }
  });
  return localJWKSet;
}
__name(createLocalJWKSet, "createLocalJWKSet");

// node_modules/jose/dist/webapi/jwks/remote.js
function isCloudflareWorkers() {
  return typeof WebSocketPair !== "undefined" || typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers" || typeof EdgeRuntime !== "undefined" && EdgeRuntime === "vercel";
}
__name(isCloudflareWorkers, "isCloudflareWorkers");
var USER_AGENT;
if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
  const NAME = "jose";
  const VERSION = "v6.1.0";
  USER_AGENT = `${NAME}/${VERSION}`;
}
var customFetch = /* @__PURE__ */ Symbol();
async function fetchJwks(url, headers, signal, fetchImpl = fetch) {
  const response = await fetchImpl(url, {
    method: "GET",
    signal,
    redirect: "manual",
    headers
  }).catch((err) => {
    if (err.name === "TimeoutError") {
      throw new JWKSTimeout();
    }
    throw err;
  });
  if (response.status !== 200) {
    throw new JOSEError("Expected 200 OK from the JSON Web Key Set HTTP response");
  }
  try {
    return await response.json();
  } catch {
    throw new JOSEError("Failed to parse the JSON Web Key Set HTTP response as JSON");
  }
}
__name(fetchJwks, "fetchJwks");
var jwksCache = /* @__PURE__ */ Symbol();
function isFreshJwksCache(input, cacheMaxAge) {
  if (typeof input !== "object" || input === null) {
    return false;
  }
  if (!("uat" in input) || typeof input.uat !== "number" || Date.now() - input.uat >= cacheMaxAge) {
    return false;
  }
  if (!("jwks" in input) || !is_object_default(input.jwks) || !Array.isArray(input.jwks.keys) || !Array.prototype.every.call(input.jwks.keys, is_object_default)) {
    return false;
  }
  return true;
}
__name(isFreshJwksCache, "isFreshJwksCache");
var RemoteJWKSet = class RemoteJWKSet2 {
  static {
    __name(this, "RemoteJWKSet");
  }
  #url;
  #timeoutDuration;
  #cooldownDuration;
  #cacheMaxAge;
  #jwksTimestamp;
  #pendingFetch;
  #headers;
  #customFetch;
  #local;
  #cache;
  constructor(url, options) {
    if (!(url instanceof URL)) {
      throw new TypeError("url must be an instance of URL");
    }
    this.#url = new URL(url.href);
    this.#timeoutDuration = typeof options?.timeoutDuration === "number" ? options?.timeoutDuration : 5e3;
    this.#cooldownDuration = typeof options?.cooldownDuration === "number" ? options?.cooldownDuration : 3e4;
    this.#cacheMaxAge = typeof options?.cacheMaxAge === "number" ? options?.cacheMaxAge : 6e5;
    this.#headers = new Headers(options?.headers);
    if (USER_AGENT && !this.#headers.has("User-Agent")) {
      this.#headers.set("User-Agent", USER_AGENT);
    }
    if (!this.#headers.has("accept")) {
      this.#headers.set("accept", "application/json");
      this.#headers.append("accept", "application/jwk-set+json");
    }
    this.#customFetch = options?.[customFetch];
    if (options?.[jwksCache] !== void 0) {
      this.#cache = options?.[jwksCache];
      if (isFreshJwksCache(options?.[jwksCache], this.#cacheMaxAge)) {
        this.#jwksTimestamp = this.#cache.uat;
        this.#local = createLocalJWKSet(this.#cache.jwks);
      }
    }
  }
  pendingFetch() {
    return !!this.#pendingFetch;
  }
  coolingDown() {
    return typeof this.#jwksTimestamp === "number" ? Date.now() < this.#jwksTimestamp + this.#cooldownDuration : false;
  }
  fresh() {
    return typeof this.#jwksTimestamp === "number" ? Date.now() < this.#jwksTimestamp + this.#cacheMaxAge : false;
  }
  jwks() {
    return this.#local?.jwks();
  }
  async getKey(protectedHeader, token) {
    if (!this.#local || !this.fresh()) {
      await this.reload();
    }
    try {
      return await this.#local(protectedHeader, token);
    } catch (err) {
      if (err instanceof JWKSNoMatchingKey) {
        if (this.coolingDown() === false) {
          await this.reload();
          return this.#local(protectedHeader, token);
        }
      }
      throw err;
    }
  }
  async reload() {
    if (this.#pendingFetch && isCloudflareWorkers()) {
      this.#pendingFetch = void 0;
    }
    this.#pendingFetch ||= fetchJwks(this.#url.href, this.#headers, AbortSignal.timeout(this.#timeoutDuration), this.#customFetch).then((json2) => {
      this.#local = createLocalJWKSet(json2);
      if (this.#cache) {
        this.#cache.uat = Date.now();
        this.#cache.jwks = json2;
      }
      this.#jwksTimestamp = Date.now();
      this.#pendingFetch = void 0;
    }).catch((err) => {
      this.#pendingFetch = void 0;
      throw err;
    });
    await this.#pendingFetch;
  }
};
function createRemoteJWKSet(url, options) {
  const set = new RemoteJWKSet(url, options);
  const remoteJWKSet = /* @__PURE__ */ __name(async (protectedHeader, token) => set.getKey(protectedHeader, token), "remoteJWKSet");
  Object.defineProperties(remoteJWKSet, {
    coolingDown: {
      get: /* @__PURE__ */ __name(() => set.coolingDown(), "get"),
      enumerable: true,
      configurable: false
    },
    fresh: {
      get: /* @__PURE__ */ __name(() => set.fresh(), "get"),
      enumerable: true,
      configurable: false
    },
    reload: {
      value: /* @__PURE__ */ __name(() => set.reload(), "value"),
      enumerable: true,
      configurable: false,
      writable: false
    },
    reloading: {
      get: /* @__PURE__ */ __name(() => set.pendingFetch(), "get"),
      enumerable: true,
      configurable: false
    },
    jwks: {
      value: /* @__PURE__ */ __name(() => set.jwks(), "value"),
      enumerable: true,
      configurable: false,
      writable: false
    }
  });
  return remoteJWKSet;
}
__name(createRemoteJWKSet, "createRemoteJWKSet");

// node_modules/jose/dist/webapi/util/decode_protected_header.js
function decodeProtectedHeader(token) {
  let protectedB64u;
  if (typeof token === "string") {
    const parts = token.split(".");
    if (parts.length === 3 || parts.length === 5) {
      ;
      [protectedB64u] = parts;
    }
  } else if (typeof token === "object" && token) {
    if ("protected" in token) {
      protectedB64u = token.protected;
    } else {
      throw new TypeError("Token does not contain a Protected Header");
    }
  }
  try {
    if (typeof protectedB64u !== "string" || !protectedB64u) {
      throw new Error();
    }
    const result = JSON.parse(decoder.decode(decode2(protectedB64u)));
    if (!is_object_default(result)) {
      throw new Error();
    }
    return result;
  } catch {
    throw new TypeError("Invalid Token or Protected Header formatting");
  }
}
__name(decodeProtectedHeader, "decodeProtectedHeader");

// node_modules/jose/dist/webapi/util/decode_jwt.js
function decodeJwt(jwt2) {
  if (typeof jwt2 !== "string") throw new JWTInvalid("JWTs must use Compact JWS serialization, JWT must be a string");
  const { 1: payload, length } = jwt2.split(".");
  if (length === 5) throw new JWTInvalid("Only JWTs using Compact JWS serialization can be decoded");
  if (length !== 3) throw new JWTInvalid("Invalid JWT");
  if (!payload) throw new JWTInvalid("JWTs must contain a payload");
  let decoded;
  try {
    decoded = decode2(payload);
  } catch {
    throw new JWTInvalid("Failed to base64url decode the payload");
  }
  let result;
  try {
    result = JSON.parse(decoder.decode(decoded));
  } catch {
    throw new JWTInvalid("Failed to parse the decoded payload as JSON");
  }
  if (!is_object_default(result)) throw new JWTInvalid("Invalid JWT Claims Set");
  return result;
}
__name(decodeJwt, "decodeJwt");

// node_modules/@better-auth/utils/dist/random.mjs
function expandAlphabet(alphabet) {
  switch (alphabet) {
    case "a-z":
      return "abcdefghijklmnopqrstuvwxyz";
    case "A-Z":
      return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    case "0-9":
      return "0123456789";
    case "-_":
      return "-_";
    default:
      throw new Error(`Unsupported alphabet: ${alphabet}`);
  }
}
__name(expandAlphabet, "expandAlphabet");
function createRandomStringGenerator(...baseAlphabets) {
  const baseCharSet = baseAlphabets.map(expandAlphabet).join("");
  if (baseCharSet.length === 0) {
    throw new Error(
      "No valid characters provided for random string generation."
    );
  }
  const baseCharSetLength = baseCharSet.length;
  return (length, ...alphabets) => {
    if (length <= 0) {
      throw new Error("Length must be a positive integer.");
    }
    let charSet = baseCharSet;
    let charSetLength = baseCharSetLength;
    if (alphabets.length > 0) {
      charSet = alphabets.map(expandAlphabet).join("");
      charSetLength = charSet.length;
    }
    const maxValid = Math.floor(256 / charSetLength) * charSetLength;
    const buf = new Uint8Array(length * 2);
    const bufLength = buf.length;
    let result = "";
    let bufIndex = bufLength;
    let rand;
    while (result.length < length) {
      if (bufIndex >= bufLength) {
        crypto.getRandomValues(buf);
        bufIndex = 0;
      }
      rand = buf[bufIndex++];
      if (rand < maxValid) {
        result += charSet[rand % charSetLength];
      }
    }
    return result;
  };
}
__name(createRandomStringGenerator, "createRandomStringGenerator");

// node_modules/better-auth/dist/shared/better-auth.B4Qoxdgc.mjs
var generateRandomString = createRandomStringGenerator(
  "a-z",
  "0-9",
  "A-Z",
  "-_"
);

// node_modules/better-auth/dist/crypto/index.mjs
async function signJWT(payload, secret, expiresIn = 3600) {
  const jwt2 = await new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1e3) + expiresIn).sign(new TextEncoder().encode(secret));
  return jwt2;
}
__name(signJWT, "signJWT");
var symmetricEncrypt = /* @__PURE__ */ __name(async ({
  key,
  data
}) => {
  const keyAsBytes = await createHash("SHA-256").digest(key);
  const dataAsBytes = utf8ToBytes(data);
  const chacha = managedNonce(xchacha20poly1305)(new Uint8Array(keyAsBytes));
  return bytesToHex(chacha.encrypt(dataAsBytes));
}, "symmetricEncrypt");
var symmetricDecrypt = /* @__PURE__ */ __name(async ({
  key,
  data
}) => {
  const keyAsBytes = await createHash("SHA-256").digest(key);
  const dataAsBytes = hexToBytes(data);
  const chacha = managedNonce(xchacha20poly1305)(new Uint8Array(keyAsBytes));
  return new TextDecoder().decode(chacha.decrypt(dataAsBytes));
}, "symmetricDecrypt");

// node_modules/@better-fetch/fetch/dist/index.js
var __defProp3 = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp2 = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = /* @__PURE__ */ __name((obj, key, value) => key in obj ? __defProp3(obj, key, {
  enumerable: true,
  configurable: true,
  writable: true,
  value
}) : obj[key] = value, "__defNormalProp");
var __spreadValues = /* @__PURE__ */ __name((a, b) => {
  for (var prop in b || (b = {})) if (__hasOwnProp2.call(b, prop)) __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols) for (var prop of __getOwnPropSymbols(b)) {
    if (__propIsEnum.call(b, prop)) __defNormalProp(a, prop, b[prop]);
  }
  return a;
}, "__spreadValues");
var __spreadProps = /* @__PURE__ */ __name((a, b) => __defProps(a, __getOwnPropDescs(b)), "__spreadProps");
var BetterFetchError = class extends Error {
  static {
    __name(this, "BetterFetchError");
  }
  constructor(status, statusText, error3) {
    super(statusText || status.toString(), {
      cause: error3
    });
    this.status = status;
    this.statusText = statusText;
    this.error = error3;
  }
};
var initializePlugins = /* @__PURE__ */ __name(async (url, options) => {
  var _a, _b, _c, _d, _e, _f;
  let opts = options || {};
  const hooks = {
    onRequest: [
      options == null ? void 0 : options.onRequest
    ],
    onResponse: [
      options == null ? void 0 : options.onResponse
    ],
    onSuccess: [
      options == null ? void 0 : options.onSuccess
    ],
    onError: [
      options == null ? void 0 : options.onError
    ],
    onRetry: [
      options == null ? void 0 : options.onRetry
    ]
  };
  if (!options || !(options == null ? void 0 : options.plugins)) {
    return {
      url,
      options: opts,
      hooks
    };
  }
  for (const plugin of (options == null ? void 0 : options.plugins) || []) {
    if (plugin.init) {
      const pluginRes = await ((_a = plugin.init) == null ? void 0 : _a.call(plugin, url.toString(), options));
      opts = pluginRes.options || opts;
      url = pluginRes.url;
    }
    hooks.onRequest.push((_b = plugin.hooks) == null ? void 0 : _b.onRequest);
    hooks.onResponse.push((_c = plugin.hooks) == null ? void 0 : _c.onResponse);
    hooks.onSuccess.push((_d = plugin.hooks) == null ? void 0 : _d.onSuccess);
    hooks.onError.push((_e = plugin.hooks) == null ? void 0 : _e.onError);
    hooks.onRetry.push((_f = plugin.hooks) == null ? void 0 : _f.onRetry);
  }
  return {
    url,
    options: opts,
    hooks
  };
}, "initializePlugins");
var LinearRetryStrategy = class {
  static {
    __name(this, "LinearRetryStrategy");
  }
  constructor(options) {
    this.options = options;
  }
  shouldAttemptRetry(attempt, response) {
    if (this.options.shouldRetry) {
      return Promise.resolve(attempt < this.options.attempts && this.options.shouldRetry(response));
    }
    return Promise.resolve(attempt < this.options.attempts);
  }
  getDelay() {
    return this.options.delay;
  }
};
var ExponentialRetryStrategy = class {
  static {
    __name(this, "ExponentialRetryStrategy");
  }
  constructor(options) {
    this.options = options;
  }
  shouldAttemptRetry(attempt, response) {
    if (this.options.shouldRetry) {
      return Promise.resolve(attempt < this.options.attempts && this.options.shouldRetry(response));
    }
    return Promise.resolve(attempt < this.options.attempts);
  }
  getDelay(attempt) {
    const delay = Math.min(this.options.maxDelay, this.options.baseDelay * 2 ** attempt);
    return delay;
  }
};
function createRetryStrategy(options) {
  if (typeof options === "number") {
    return new LinearRetryStrategy({
      type: "linear",
      attempts: options,
      delay: 1e3
    });
  }
  switch (options.type) {
    case "linear":
      return new LinearRetryStrategy(options);
    case "exponential":
      return new ExponentialRetryStrategy(options);
    default:
      throw new Error("Invalid retry strategy");
  }
}
__name(createRetryStrategy, "createRetryStrategy");
var getAuthHeader = /* @__PURE__ */ __name(async (options) => {
  const headers = {};
  const getValue = /* @__PURE__ */ __name(async (value) => typeof value === "function" ? await value() : value, "getValue");
  if (options == null ? void 0 : options.auth) {
    if (options.auth.type === "Bearer") {
      const token = await getValue(options.auth.token);
      if (!token) {
        return headers;
      }
      headers["authorization"] = `Bearer ${token}`;
    } else if (options.auth.type === "Basic") {
      const username2 = getValue(options.auth.username);
      const password = getValue(options.auth.password);
      if (!username2 || !password) {
        return headers;
      }
      headers["authorization"] = `Basic ${btoa(`${username2}:${password}`)}`;
    } else if (options.auth.type === "Custom") {
      const value = getValue(options.auth.value);
      if (!value) {
        return headers;
      }
      headers["authorization"] = `${getValue(options.auth.prefix)} ${value}`;
    }
  }
  return headers;
}, "getAuthHeader");
var JSON_RE = /^application\/(?:[\w!#$%&*.^`~-]*\+)?json(;.+)?$/i;
function detectResponseType(request) {
  const _contentType = request.headers.get("content-type");
  const textTypes = /* @__PURE__ */ new Set([
    "image/svg",
    "application/xml",
    "application/xhtml",
    "application/html"
  ]);
  if (!_contentType) {
    return "json";
  }
  const contentType = _contentType.split(";").shift() || "";
  if (JSON_RE.test(contentType)) {
    return "json";
  }
  if (textTypes.has(contentType) || contentType.startsWith("text/")) {
    return "text";
  }
  return "blob";
}
__name(detectResponseType, "detectResponseType");
function isJSONParsable(value) {
  try {
    JSON.parse(value);
    return true;
  } catch (error3) {
    return false;
  }
}
__name(isJSONParsable, "isJSONParsable");
function isJSONSerializable2(value) {
  if (value === void 0) {
    return false;
  }
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean" || t === null) {
    return true;
  }
  if (t !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return true;
  }
  if (value.buffer) {
    return false;
  }
  return value.constructor && value.constructor.name === "Object" || typeof value.toJSON === "function";
}
__name(isJSONSerializable2, "isJSONSerializable");
function jsonParse(text) {
  try {
    return JSON.parse(text);
  } catch (error3) {
    return text;
  }
}
__name(jsonParse, "jsonParse");
function isFunction(value) {
  return typeof value === "function";
}
__name(isFunction, "isFunction");
function getFetch(options) {
  if (options == null ? void 0 : options.customFetchImpl) {
    return options.customFetchImpl;
  }
  if (typeof globalThis !== "undefined" && isFunction(globalThis.fetch)) {
    return globalThis.fetch;
  }
  if (typeof window !== "undefined" && isFunction(window.fetch)) {
    return window.fetch;
  }
  throw new Error("No fetch implementation found");
}
__name(getFetch, "getFetch");
async function getHeaders(opts) {
  const headers = new Headers(opts == null ? void 0 : opts.headers);
  const authHeader = await getAuthHeader(opts);
  for (const [key, value] of Object.entries(authHeader || {})) {
    headers.set(key, value);
  }
  if (!headers.has("content-type")) {
    const t = detectContentType(opts == null ? void 0 : opts.body);
    if (t) {
      headers.set("content-type", t);
    }
  }
  return headers;
}
__name(getHeaders, "getHeaders");
function detectContentType(body) {
  if (isJSONSerializable2(body)) {
    return "application/json";
  }
  return null;
}
__name(detectContentType, "detectContentType");
function getBody(options) {
  if (!(options == null ? void 0 : options.body)) {
    return null;
  }
  const headers = new Headers(options == null ? void 0 : options.headers);
  if (isJSONSerializable2(options.body) && !headers.has("content-type")) {
    for (const [key, value] of Object.entries(options == null ? void 0 : options.body)) {
      if (value instanceof Date) {
        options.body[key] = value.toISOString();
      }
    }
    return JSON.stringify(options.body);
  }
  return options.body;
}
__name(getBody, "getBody");
function getMethod(url, options) {
  var _a;
  if (options == null ? void 0 : options.method) {
    return options.method.toUpperCase();
  }
  if (url.startsWith("@")) {
    const pMethod = (_a = url.split("@")[1]) == null ? void 0 : _a.split("/")[0];
    if (!methods.includes(pMethod)) {
      return (options == null ? void 0 : options.body) ? "POST" : "GET";
    }
    return pMethod.toUpperCase();
  }
  return (options == null ? void 0 : options.body) ? "POST" : "GET";
}
__name(getMethod, "getMethod");
function getTimeout(options, controller) {
  let abortTimeout;
  if (!(options == null ? void 0 : options.signal) && (options == null ? void 0 : options.timeout)) {
    abortTimeout = setTimeout(() => controller == null ? void 0 : controller.abort(), options == null ? void 0 : options.timeout);
  }
  return {
    abortTimeout,
    clearTimeout: /* @__PURE__ */ __name(() => {
      if (abortTimeout) {
        clearTimeout(abortTimeout);
      }
    }, "clearTimeout")
  };
}
__name(getTimeout, "getTimeout");
var ValidationError = class _ValidationError extends Error {
  static {
    __name(this, "_ValidationError");
  }
  constructor(issues, message2) {
    super(message2 || JSON.stringify(issues, null, 2));
    this.issues = issues;
    Object.setPrototypeOf(this, _ValidationError.prototype);
  }
};
async function parseStandardSchema(schema3, input) {
  let result = await schema3["~standard"].validate(input);
  if (result.issues) {
    throw new ValidationError(result.issues);
  }
  return result.value;
}
__name(parseStandardSchema, "parseStandardSchema");
var methods = [
  "get",
  "post",
  "put",
  "patch",
  "delete"
];
function getURL2(url, option) {
  let { baseURL, params, query } = option || {
    query: {},
    params: {},
    baseURL: ""
  };
  let basePath = url.startsWith("http") ? url.split("/").slice(0, 3).join("/") : baseURL || "";
  if (url.startsWith("@")) {
    const m2 = url.toString().split("@")[1].split("/")[0];
    if (methods.includes(m2)) {
      url = url.replace(`@${m2}/`, "/");
    }
  }
  if (!basePath.endsWith("/")) basePath += "/";
  let [path, urlQuery] = url.replace(basePath, "").split("?");
  const queryParams = new URLSearchParams(urlQuery);
  for (const [key, value] of Object.entries(query || {})) {
    if (value == null) continue;
    queryParams.set(key, String(value));
  }
  if (params) {
    if (Array.isArray(params)) {
      const paramPaths = path.split("/").filter((p) => p.startsWith(":"));
      for (const [index, key] of paramPaths.entries()) {
        const value = params[index];
        path = path.replace(key, value);
      }
    } else {
      for (const [key, value] of Object.entries(params)) {
        path = path.replace(`:${key}`, String(value));
      }
    }
  }
  path = path.split("/").map(encodeURIComponent).join("/");
  if (path.startsWith("/")) path = path.slice(1);
  let queryParamString = queryParams.toString();
  queryParamString = queryParamString.length > 0 ? `?${queryParamString}`.replace(/\+/g, "%20") : "";
  if (!basePath.startsWith("http")) {
    return `${basePath}${path}${queryParamString}`;
  }
  const _url2 = new URL(`${path}${queryParamString}`, basePath);
  return _url2;
}
__name(getURL2, "getURL2");
var betterFetch = /* @__PURE__ */ __name(async (url, options) => {
  var _a, _b, _c, _d, _e, _f, _g, _h;
  const { hooks, url: __url, options: opts } = await initializePlugins(url, options);
  const fetch2 = getFetch(opts);
  const controller = new AbortController();
  const signal = (_a = opts.signal) != null ? _a : controller.signal;
  const _url2 = getURL2(__url, opts);
  const body = getBody(opts);
  const headers = await getHeaders(opts);
  const method = getMethod(__url, opts);
  let context = __spreadProps(__spreadValues({}, opts), {
    url: _url2,
    headers,
    body,
    method,
    signal
  });
  for (const onRequest of hooks.onRequest) {
    if (onRequest) {
      const res = await onRequest(context);
      if (res instanceof Object) {
        context = res;
      }
    }
  }
  if ("pipeTo" in context && typeof context.pipeTo === "function" || typeof ((_b = options == null ? void 0 : options.body) == null ? void 0 : _b.pipe) === "function") {
    if (!("duplex" in context)) {
      context.duplex = "half";
    }
  }
  const { clearTimeout: clearTimeout2 } = getTimeout(opts, controller);
  let response = await fetch2(context.url, context);
  clearTimeout2();
  const responseContext = {
    response,
    request: context
  };
  for (const onResponse of hooks.onResponse) {
    if (onResponse) {
      const r = await onResponse(__spreadProps(__spreadValues({}, responseContext), {
        response: ((_c = options == null ? void 0 : options.hookOptions) == null ? void 0 : _c.cloneResponse) ? response.clone() : response
      }));
      if (r instanceof Response) {
        response = r;
      } else if (r instanceof Object) {
        response = r.response;
      }
    }
  }
  if (response.ok) {
    const hasBody = context.method !== "HEAD";
    if (!hasBody) {
      return {
        data: "",
        error: null
      };
    }
    const responseType = detectResponseType(response);
    const successContext = {
      data: "",
      response,
      request: context
    };
    if (responseType === "json" || responseType === "text") {
      const text = await response.text();
      const parser2 = (_d = context.jsonParser) != null ? _d : jsonParse;
      const data = await parser2(text);
      successContext.data = data;
    } else {
      successContext.data = await response[responseType]();
    }
    if (context == null ? void 0 : context.output) {
      if (context.output && !context.disableValidation) {
        successContext.data = await parseStandardSchema(context.output, successContext.data);
      }
    }
    for (const onSuccess of hooks.onSuccess) {
      if (onSuccess) {
        await onSuccess(__spreadProps(__spreadValues({}, successContext), {
          response: ((_e = options == null ? void 0 : options.hookOptions) == null ? void 0 : _e.cloneResponse) ? response.clone() : response
        }));
      }
    }
    if (options == null ? void 0 : options.throw) {
      return successContext.data;
    }
    return {
      data: successContext.data,
      error: null
    };
  }
  const parser = (_f = options == null ? void 0 : options.jsonParser) != null ? _f : jsonParse;
  const responseText = await response.text();
  const isJSONResponse2 = isJSONParsable(responseText);
  const errorObject = isJSONResponse2 ? await parser(responseText) : null;
  const errorContext = {
    response,
    responseText,
    request: context,
    error: __spreadProps(__spreadValues({}, errorObject), {
      status: response.status,
      statusText: response.statusText
    })
  };
  for (const onError of hooks.onError) {
    if (onError) {
      await onError(__spreadProps(__spreadValues({}, errorContext), {
        response: ((_g = options == null ? void 0 : options.hookOptions) == null ? void 0 : _g.cloneResponse) ? response.clone() : response
      }));
    }
  }
  if (options == null ? void 0 : options.retry) {
    const retryStrategy = createRetryStrategy(options.retry);
    const _retryAttempt = (_h = options.retryAttempt) != null ? _h : 0;
    if (await retryStrategy.shouldAttemptRetry(_retryAttempt, response)) {
      for (const onRetry of hooks.onRetry) {
        if (onRetry) {
          await onRetry(responseContext);
        }
      }
      const delay = retryStrategy.getDelay(_retryAttempt);
      await new Promise((resolve) => setTimeout(resolve, delay));
      return await betterFetch(url, __spreadProps(__spreadValues({}, options), {
        retryAttempt: _retryAttempt + 1
      }));
    }
  }
  if (options == null ? void 0 : options.throw) {
    throw new BetterFetchError(response.status, response.statusText, isJSONResponse2 ? errorObject : responseText);
  }
  return {
    data: null,
    error: __spreadProps(__spreadValues({}, errorObject), {
      status: response.status,
      statusText: response.statusText
    })
  };
}, "betterFetch");

// node_modules/better-auth/dist/shared/better-auth.BUPPRXfK.mjs
var generateId = /* @__PURE__ */ __name((size) => {
  return createRandomStringGenerator("a-z", "A-Z", "0-9")(size || 32);
}, "generateId");

// node_modules/@better-auth/core/dist/db/index.mjs
var coreSchema = object({
  id: string2(),
  createdAt: date3().default(() => /* @__PURE__ */ new Date()),
  updatedAt: date3().default(() => /* @__PURE__ */ new Date())
});
var userSchema = coreSchema.extend({
  email: string2().transform((val) => val.toLowerCase()),
  emailVerified: boolean2().default(false),
  name: string2(),
  image: string2().nullish()
});
var accountSchema = coreSchema.extend({
  providerId: string2(),
  accountId: string2(),
  userId: coerce_exports.string(),
  accessToken: string2().nullish(),
  refreshToken: string2().nullish(),
  idToken: string2().nullish(),
  /**
   * Access token expires at
   */
  accessTokenExpiresAt: date3().nullish(),
  /**
   * Refresh token expires at
   */
  refreshTokenExpiresAt: date3().nullish(),
  /**
   * The scopes that the user has authorized
   */
  scope: string2().nullish(),
  /**
   * Password is only stored in the credential provider
   */
  password: string2().nullish()
});
var sessionSchema = coreSchema.extend({
  userId: coerce_exports.string(),
  expiresAt: date3(),
  token: string2(),
  ipAddress: string2().nullish(),
  userAgent: string2().nullish()
});
var verificationSchema = coreSchema.extend({
  value: string2(),
  expiresAt: date3(),
  identifier: string2()
});

// node_modules/defu/dist/defu.mjs
function isPlainObject3(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype && Object.getPrototypeOf(prototype) !== null) {
    return false;
  }
  if (Symbol.iterator in value) {
    return false;
  }
  if (Symbol.toStringTag in value) {
    return Object.prototype.toString.call(value) === "[object Module]";
  }
  return true;
}
__name(isPlainObject3, "isPlainObject");
function _defu(baseObject, defaults, namespace = ".", merger) {
  if (!isPlainObject3(defaults)) {
    return _defu(baseObject, {}, namespace, merger);
  }
  const object2 = Object.assign({}, defaults);
  for (const key in baseObject) {
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    const value = baseObject[key];
    if (value === null || value === void 0) {
      continue;
    }
    if (merger && merger(object2, key, value, namespace)) {
      continue;
    }
    if (Array.isArray(value) && Array.isArray(object2[key])) {
      object2[key] = [...value, ...object2[key]];
    } else if (isPlainObject3(value) && isPlainObject3(object2[key])) {
      object2[key] = _defu(
        value,
        object2[key],
        (namespace ? `${namespace}.` : "") + key.toString(),
        merger
      );
    } else {
      object2[key] = value;
    }
  }
  return object2;
}
__name(_defu, "_defu");
function createDefu(merger) {
  return (...arguments_) => (
    // eslint-disable-next-line unicorn/no-array-reduce
    arguments_.reduce((p, c) => _defu(p, c, "", merger), {})
  );
}
__name(createDefu, "createDefu");
var defu = createDefu();
var defuFn = createDefu((object2, key, currentValue) => {
  if (object2[key] !== void 0 && typeof currentValue === "function") {
    object2[key] = currentValue(object2[key]);
    return true;
  }
});
var defuArrayFn = createDefu((object2, key, currentValue) => {
  if (Array.isArray(object2[key]) && typeof currentValue === "function") {
    object2[key] = currentValue(object2[key]);
    return true;
  }
});

// node_modules/better-auth/dist/shared/better-auth.C3-_8m-g.mjs
function escapeRegExpChar(char) {
  if (char === "-" || char === "^" || char === "$" || char === "+" || char === "." || char === "(" || char === ")" || char === "|" || char === "[" || char === "]" || char === "{" || char === "}" || char === "*" || char === "?" || char === "\\") {
    return `\\${char}`;
  } else {
    return char;
  }
}
__name(escapeRegExpChar, "escapeRegExpChar");
function escapeRegExpString(str) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    result += escapeRegExpChar(str[i]);
  }
  return result;
}
__name(escapeRegExpString, "escapeRegExpString");
function transform2(pattern, separator = true) {
  if (Array.isArray(pattern)) {
    let regExpPatterns = pattern.map((p) => `^${transform2(p, separator)}$`);
    return `(?:${regExpPatterns.join("|")})`;
  }
  let separatorSplitter = "";
  let separatorMatcher = "";
  let wildcard = ".";
  if (separator === true) {
    separatorSplitter = "/";
    separatorMatcher = "[/\\\\]";
    wildcard = "[^/\\\\]";
  } else if (separator) {
    separatorSplitter = separator;
    separatorMatcher = escapeRegExpString(separatorSplitter);
    if (separatorMatcher.length > 1) {
      separatorMatcher = `(?:${separatorMatcher})`;
      wildcard = `((?!${separatorMatcher}).)`;
    } else {
      wildcard = `[^${separatorMatcher}]`;
    }
  }
  let requiredSeparator = separator ? `${separatorMatcher}+?` : "";
  let optionalSeparator = separator ? `${separatorMatcher}*?` : "";
  let segments = separator ? pattern.split(separatorSplitter) : [pattern];
  let result = "";
  for (let s2 = 0; s2 < segments.length; s2++) {
    let segment = segments[s2];
    let nextSegment = segments[s2 + 1];
    let currentSeparator = "";
    if (!segment && s2 > 0) {
      continue;
    }
    if (separator) {
      if (s2 === segments.length - 1) {
        currentSeparator = optionalSeparator;
      } else if (nextSegment !== "**") {
        currentSeparator = requiredSeparator;
      } else {
        currentSeparator = "";
      }
    }
    if (separator && segment === "**") {
      if (currentSeparator) {
        result += s2 === 0 ? "" : currentSeparator;
        result += `(?:${wildcard}*?${currentSeparator})*?`;
      }
      continue;
    }
    for (let c = 0; c < segment.length; c++) {
      let char = segment[c];
      if (char === "\\") {
        if (c < segment.length - 1) {
          result += escapeRegExpChar(segment[c + 1]);
          c++;
        }
      } else if (char === "?") {
        result += wildcard;
      } else if (char === "*") {
        result += `${wildcard}*?`;
      } else {
        result += escapeRegExpChar(char);
      }
    }
    result += currentSeparator;
  }
  return result;
}
__name(transform2, "transform");
function isMatch(regexp, sample) {
  if (typeof sample !== "string") {
    throw new TypeError(`Sample must be a string, but ${typeof sample} given`);
  }
  return regexp.test(sample);
}
__name(isMatch, "isMatch");
function wildcardMatch(pattern, options) {
  if (typeof pattern !== "string" && !Array.isArray(pattern)) {
    throw new TypeError(
      `The first argument must be a single pattern string or an array of patterns, but ${typeof pattern} given`
    );
  }
  if (typeof options === "string" || typeof options === "boolean") {
    options = { separator: options };
  }
  if (arguments.length === 2 && !(typeof options === "undefined" || typeof options === "object" && options !== null && !Array.isArray(options))) {
    throw new TypeError(
      `The second argument must be an options object or a string/boolean separator, but ${typeof options} given`
    );
  }
  options = options || {};
  if (options.separator === "\\") {
    throw new Error(
      "\\ is not a valid separator because it is used for escaping. Try setting the separator to `true` instead"
    );
  }
  let regexpPattern = transform2(pattern, options.separator);
  let regexp = new RegExp(`^${regexpPattern}$`, options.flags);
  let fn = isMatch.bind(null, regexp);
  fn.options = options;
  fn.pattern = pattern;
  fn.regexp = regexp;
  return fn;
}
__name(wildcardMatch, "wildcardMatch");
var originCheckMiddleware = createAuthMiddleware(async (ctx) => {
  if (ctx.request?.method !== "POST" || !ctx.request) {
    return;
  }
  const { body, query, context } = ctx;
  const originHeader = ctx.headers?.get("origin") || ctx.headers?.get("referer") || "";
  const callbackURL = body?.callbackURL || query?.callbackURL;
  const redirectURL = body?.redirectTo;
  const errorCallbackURL = body?.errorCallbackURL;
  const newUserCallbackURL = body?.newUserCallbackURL;
  const trustedOrigins = Array.isArray(context.options.trustedOrigins) ? context.trustedOrigins : [
    ...context.trustedOrigins,
    ...await context.options.trustedOrigins?.(ctx.request) || []
  ];
  const usesCookies = ctx.headers?.has("cookie");
  const matchesPattern = /* @__PURE__ */ __name((url, pattern) => {
    if (url.startsWith("/")) {
      return false;
    }
    if (pattern.includes("*")) {
      if (pattern.includes("://")) {
        return wildcardMatch(pattern)(getOrigin(url) || url);
      }
      return wildcardMatch(pattern)(getHost(url));
    }
    const protocol = getProtocol(url);
    return protocol === "http:" || protocol === "https:" || !protocol ? pattern === getOrigin(url) : url.startsWith(pattern);
  }, "matchesPattern");
  const validateURL = /* @__PURE__ */ __name((url, label) => {
    if (!url) {
      return;
    }
    const isTrustedOrigin = trustedOrigins.some(
      (origin) => matchesPattern(url, origin) || url?.startsWith("/") && label !== "origin" && /^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$/.test(url)
    );
    if (!isTrustedOrigin) {
      ctx.context.logger.error(`Invalid ${label}: ${url}`);
      ctx.context.logger.info(
        `If it's a valid URL, please add ${url} to trustedOrigins in your auth config
`,
        `Current list of trustedOrigins: ${trustedOrigins}`
      );
      throw new APIError("FORBIDDEN", { message: `Invalid ${label}` });
    }
  }, "validateURL");
  if (usesCookies && !ctx.context.options.advanced?.disableCSRFCheck) {
    validateURL(originHeader, "origin");
  }
  callbackURL && validateURL(callbackURL, "callbackURL");
  redirectURL && validateURL(redirectURL, "redirectURL");
  errorCallbackURL && validateURL(errorCallbackURL, "errorCallbackURL");
  newUserCallbackURL && validateURL(newUserCallbackURL, "newUserCallbackURL");
});
var originCheck = /* @__PURE__ */ __name((getValue) => createAuthMiddleware(async (ctx) => {
  if (!ctx.request) {
    return;
  }
  const { context } = ctx;
  const callbackURL = getValue(ctx);
  const trustedOrigins = Array.isArray(
    context.options.trustedOrigins
  ) ? context.trustedOrigins : [
    ...context.trustedOrigins,
    ...await context.options.trustedOrigins?.(ctx.request) || []
  ];
  const matchesPattern = /* @__PURE__ */ __name((url, pattern) => {
    if (url.startsWith("/")) {
      return false;
    }
    if (pattern.includes("*")) {
      if (pattern.includes("://")) {
        return wildcardMatch(pattern)(getOrigin(url) || url);
      }
      return wildcardMatch(pattern)(getHost(url));
    }
    const protocol = getProtocol(url);
    return protocol === "http:" || protocol === "https:" || !protocol ? pattern === getOrigin(url) : url.startsWith(pattern);
  }, "matchesPattern");
  const validateURL = /* @__PURE__ */ __name((url, label) => {
    if (!url) {
      return;
    }
    const isTrustedOrigin = trustedOrigins.some(
      (origin) => matchesPattern(url, origin) || url?.startsWith("/") && label !== "origin" && /^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$/.test(
        url
      )
    );
    if (!isTrustedOrigin) {
      ctx.context.logger.error(`Invalid ${label}: ${url}`);
      ctx.context.logger.info(
        `If it's a valid URL, please add ${url} to trustedOrigins in your auth config
`,
        `Current list of trustedOrigins: ${trustedOrigins}`
      );
      throw new APIError("FORBIDDEN", { message: `Invalid ${label}` });
    }
  }, "validateURL");
  const callbacks = Array.isArray(callbackURL) ? callbackURL : [callbackURL];
  for (const url of callbacks) {
    validateURL(url, "callbackURL");
  }
}), "originCheck");
async function createEmailVerificationToken(secret, email3, updateTo, expiresIn = 3600) {
  const token = await signJWT(
    {
      email: email3.toLowerCase(),
      updateTo
    },
    secret,
    expiresIn
  );
  return token;
}
__name(createEmailVerificationToken, "createEmailVerificationToken");
async function sendVerificationEmailFn(ctx, user) {
  if (!ctx.context.options.emailVerification?.sendVerificationEmail) {
    ctx.context.logger.error("Verification email isn't enabled.");
    throw new APIError("BAD_REQUEST", {
      message: "Verification email isn't enabled"
    });
  }
  const token = await createEmailVerificationToken(
    ctx.context.secret,
    user.email,
    void 0,
    ctx.context.options.emailVerification?.expiresIn
  );
  const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${ctx.body.callbackURL || "/"}`;
  await ctx.context.options.emailVerification.sendVerificationEmail(
    {
      user,
      url,
      token
    },
    ctx.request
  );
}
__name(sendVerificationEmailFn, "sendVerificationEmailFn");
var sendVerificationEmail = createAuthEndpoint(
  "/send-verification-email",
  {
    method: "POST",
    body: object({
      email: email2().meta({
        description: "The email to send the verification email to"
      }),
      callbackURL: string2().meta({
        description: "The URL to use for email verification callback"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Send a verification email to the user",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  email: {
                    type: "string",
                    description: "The email to send the verification email to",
                    example: "user@example.com"
                  },
                  callbackURL: {
                    type: "string",
                    description: "The URL to use for email verification callback",
                    example: "https://example.com/callback",
                    nullable: true
                  }
                },
                required: ["email"]
              }
            }
          }
        },
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean",
                      description: "Indicates if the email was sent successfully",
                      example: true
                    }
                  }
                }
              }
            }
          },
          "400": {
            description: "Bad Request",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    message: {
                      type: "string",
                      description: "Error message",
                      example: "Verification email isn't enabled"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.emailVerification?.sendVerificationEmail) {
      ctx.context.logger.error("Verification email isn't enabled.");
      throw new APIError("BAD_REQUEST", {
        message: "Verification email isn't enabled"
      });
    }
    const { email: email3 } = ctx.body;
    const session = await getSessionFromCtx(ctx);
    if (!session) {
      const user = await ctx.context.internalAdapter.findUserByEmail(email3);
      if (!user) {
        return ctx.json({
          status: true
        });
      }
      await sendVerificationEmailFn(ctx, user.user);
      return ctx.json({
        status: true
      });
    }
    if (session?.user.emailVerified) {
      throw new APIError("BAD_REQUEST", {
        message: "You can only send a verification email to an unverified email"
      });
    }
    if (session?.user.email !== email3) {
      throw new APIError("BAD_REQUEST", {
        message: "You can only send a verification email to your own email"
      });
    }
    await sendVerificationEmailFn(ctx, session.user);
    return ctx.json({
      status: true
    });
  }
);
var verifyEmail = createAuthEndpoint(
  "/verify-email",
  {
    method: "GET",
    query: object({
      token: string2().meta({
        description: "The token to verify the email"
      }),
      callbackURL: string2().meta({
        description: "The URL to redirect to after email verification"
      }).optional()
    }),
    use: [originCheck((ctx) => ctx.query.callbackURL)],
    metadata: {
      openapi: {
        description: "Verify the email of the user",
        parameters: [
          {
            name: "token",
            in: "query",
            description: "The token to verify the email",
            required: true,
            schema: {
              type: "string"
            }
          },
          {
            name: "callbackURL",
            in: "query",
            description: "The URL to redirect to after email verification",
            required: false,
            schema: {
              type: "string"
            }
          }
        ],
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    user: {
                      type: "object",
                      properties: {
                        id: {
                          type: "string",
                          description: "User ID"
                        },
                        email: {
                          type: "string",
                          description: "User email"
                        },
                        name: {
                          type: "string",
                          description: "User name"
                        },
                        image: {
                          type: "string",
                          description: "User image URL"
                        },
                        emailVerified: {
                          type: "boolean",
                          description: "Indicates if the user email is verified"
                        },
                        createdAt: {
                          type: "string",
                          description: "User creation date"
                        },
                        updatedAt: {
                          type: "string",
                          description: "User update date"
                        }
                      },
                      required: [
                        "id",
                        "email",
                        "name",
                        "image",
                        "emailVerified",
                        "createdAt",
                        "updatedAt"
                      ]
                    },
                    status: {
                      type: "boolean",
                      description: "Indicates if the email was verified successfully"
                    }
                  },
                  required: ["user", "status"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    function redirectOnError(error3) {
      if (ctx.query.callbackURL) {
        if (ctx.query.callbackURL.includes("?")) {
          throw ctx.redirect(`${ctx.query.callbackURL}&error=${error3}`);
        }
        throw ctx.redirect(`${ctx.query.callbackURL}?error=${error3}`);
      }
      throw new APIError("UNAUTHORIZED", {
        message: error3
      });
    }
    __name(redirectOnError, "redirectOnError");
    const { token } = ctx.query;
    let jwt2;
    try {
      jwt2 = await jwtVerify(
        token,
        new TextEncoder().encode(ctx.context.secret),
        {
          algorithms: ["HS256"]
        }
      );
    } catch (e) {
      if (e instanceof JWTExpired) {
        return redirectOnError("token_expired");
      }
      return redirectOnError("invalid_token");
    }
    const schema3 = object({
      email: string2().email(),
      updateTo: string2().optional()
    });
    const parsed = schema3.parse(jwt2.payload);
    const user = await ctx.context.internalAdapter.findUserByEmail(
      parsed.email
    );
    if (!user) {
      return redirectOnError("user_not_found");
    }
    if (parsed.updateTo) {
      const session = await getSessionFromCtx(ctx);
      if (!session) {
        if (ctx.query.callbackURL) {
          throw ctx.redirect(`${ctx.query.callbackURL}?error=unauthorized`);
        }
        return redirectOnError("unauthorized");
      }
      if (session.user.email !== parsed.email) {
        if (ctx.query.callbackURL) {
          throw ctx.redirect(`${ctx.query.callbackURL}?error=unauthorized`);
        }
        return redirectOnError("unauthorized");
      }
      const updatedUser2 = await ctx.context.internalAdapter.updateUserByEmail(
        parsed.email,
        {
          email: parsed.updateTo,
          emailVerified: false
        },
        ctx
      );
      const newToken = await createEmailVerificationToken(
        ctx.context.secret,
        parsed.updateTo
      );
      await ctx.context.options.emailVerification?.sendVerificationEmail?.(
        {
          user: updatedUser2,
          url: `${ctx.context.baseURL}/verify-email?token=${newToken}&callbackURL=${ctx.query.callbackURL || "/"}`,
          token: newToken
        },
        ctx.request
      );
      await setSessionCookie(ctx, {
        session: session.session,
        user: {
          ...session.user,
          email: parsed.updateTo,
          emailVerified: false
        }
      });
      if (ctx.query.callbackURL) {
        throw ctx.redirect(ctx.query.callbackURL);
      }
      return ctx.json({
        status: true,
        user: {
          id: updatedUser2.id,
          email: updatedUser2.email,
          name: updatedUser2.name,
          image: updatedUser2.image,
          emailVerified: updatedUser2.emailVerified,
          createdAt: updatedUser2.createdAt,
          updatedAt: updatedUser2.updatedAt
        }
      });
    }
    if (ctx.context.options.emailVerification?.onEmailVerification) {
      await ctx.context.options.emailVerification.onEmailVerification(
        user.user,
        ctx.request
      );
    }
    const updatedUser = await ctx.context.internalAdapter.updateUserByEmail(
      parsed.email,
      {
        emailVerified: true
      },
      ctx
    );
    if (ctx.context.options.emailVerification?.afterEmailVerification) {
      await ctx.context.options.emailVerification.afterEmailVerification(
        updatedUser,
        ctx.request
      );
    }
    if (ctx.context.options.emailVerification?.autoSignInAfterVerification) {
      const currentSession = await getSessionFromCtx(ctx);
      if (!currentSession || currentSession.user.email !== parsed.email) {
        const session = await ctx.context.internalAdapter.createSession(
          user.user.id,
          ctx
        );
        if (!session) {
          throw new APIError("INTERNAL_SERVER_ERROR", {
            message: "Failed to create session"
          });
        }
        await setSessionCookie(ctx, {
          session,
          user: {
            ...user.user,
            emailVerified: true
          }
        });
      } else {
        await setSessionCookie(ctx, {
          session: currentSession.session,
          user: {
            ...currentSession.user,
            emailVerified: true
          }
        });
      }
    }
    if (ctx.query.callbackURL) {
      throw ctx.redirect(ctx.query.callbackURL);
    }
    return ctx.json({
      status: true,
      user: null
    });
  }
);
var HIDE_METADATA = {
  isAction: false
};
async function generateState(c, link) {
  const callbackURL = c.body?.callbackURL || c.context.options.baseURL;
  if (!callbackURL) {
    throw new APIError("BAD_REQUEST", {
      message: "callbackURL is required"
    });
  }
  const codeVerifier = generateRandomString(128);
  const state = generateRandomString(32);
  const stateCookie = c.context.createAuthCookie("state", {
    maxAge: 5 * 60 * 1e3
    // 5 minutes
  });
  await c.setSignedCookie(
    stateCookie.name,
    state,
    c.context.secret,
    stateCookie.attributes
  );
  const data = JSON.stringify({
    callbackURL,
    codeVerifier,
    errorURL: c.body?.errorCallbackURL,
    newUserURL: c.body?.newUserCallbackURL,
    link,
    /**
     * This is the actual expiry time of the state
     */
    expiresAt: Date.now() + 10 * 60 * 1e3,
    requestSignUp: c.body?.requestSignUp
  });
  const expiresAt = /* @__PURE__ */ new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + 10);
  const verification = await c.context.internalAdapter.createVerificationValue(
    {
      value: data,
      identifier: state,
      expiresAt
    },
    c
  );
  if (!verification) {
    c.context.logger.error(
      "Unable to create verification. Make sure the database adapter is properly working and there is a verification table in the database"
    );
    throw new APIError("INTERNAL_SERVER_ERROR", {
      message: "Unable to create verification"
    });
  }
  return {
    state: verification.identifier,
    codeVerifier
  };
}
__name(generateState, "generateState");
async function parseState(c) {
  const state = c.query.state || c.body.state;
  const data = await c.context.internalAdapter.findVerificationValue(state);
  if (!data) {
    c.context.logger.error("State Mismatch. Verification not found", {
      state
    });
    const errorURL = c.context.options.onAPIError?.errorURL || `${c.context.baseURL}/error`;
    throw c.redirect(`${errorURL}?error=please_restart_the_process`);
  }
  const parsedData = object({
    callbackURL: string2(),
    codeVerifier: string2(),
    errorURL: string2().optional(),
    newUserURL: string2().optional(),
    expiresAt: number2(),
    link: object({
      email: string2(),
      userId: coerce_exports.string()
    }).optional(),
    requestSignUp: boolean2().optional()
  }).parse(JSON.parse(data.value));
  if (!parsedData.errorURL) {
    parsedData.errorURL = `${c.context.baseURL}/error`;
  }
  const stateCookie = c.context.createAuthCookie("state");
  const stateCookieValue = await c.getSignedCookie(
    stateCookie.name,
    c.context.secret
  );
  const skipStateCookieCheck = c.context.oauthConfig?.skipStateCookieCheck;
  if (!skipStateCookieCheck && (!stateCookieValue || stateCookieValue !== state)) {
    const errorURL = c.context.options.onAPIError?.errorURL || `${c.context.baseURL}/error`;
    throw c.redirect(`${errorURL}?error=state_mismatch`);
  }
  c.setCookie(stateCookie.name, "", {
    maxAge: 0
  });
  if (parsedData.expiresAt < Date.now()) {
    await c.context.internalAdapter.deleteVerificationValue(data.id);
    const errorURL = c.context.options.onAPIError?.errorURL || `${c.context.baseURL}/error`;
    throw c.redirect(`${errorURL}?error=please_restart_the_process`);
  }
  await c.context.internalAdapter.deleteVerificationValue(data.id);
  return parsedData;
}
__name(parseState, "parseState");
async function generateCodeChallenge(codeVerifier) {
  const codeChallengeBytes = await createHash("SHA-256").digest(codeVerifier);
  return base64Url.encode(new Uint8Array(codeChallengeBytes), {
    padding: false
  });
}
__name(generateCodeChallenge, "generateCodeChallenge");
function getOAuth2Tokens(data) {
  return {
    tokenType: data.token_type,
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    accessTokenExpiresAt: data.expires_in ? getDate(data.expires_in, "sec") : void 0,
    refreshTokenExpiresAt: data.refresh_token_expires_in ? getDate(data.refresh_token_expires_in, "sec") : void 0,
    scopes: data?.scope ? typeof data.scope === "string" ? data.scope.split(" ") : data.scope : [],
    idToken: data.id_token
  };
}
__name(getOAuth2Tokens, "getOAuth2Tokens");
function decryptOAuthToken(token, ctx) {
  if (!token) return token;
  if (ctx.options.account?.encryptOAuthTokens) {
    return symmetricDecrypt({
      key: ctx.secret,
      data: token
    });
  }
  return token;
}
__name(decryptOAuthToken, "decryptOAuthToken");
function setTokenUtil(token, ctx) {
  if (ctx.options.account?.encryptOAuthTokens && token) {
    return symmetricEncrypt({
      key: ctx.secret,
      data: token
    });
  }
  return token;
}
__name(setTokenUtil, "setTokenUtil");
async function handleOAuthUserInfo(c, {
  userInfo,
  account,
  callbackURL,
  disableSignUp,
  overrideUserInfo
}) {
  const dbUser = await c.context.internalAdapter.findOAuthUser(
    userInfo.email.toLowerCase(),
    account.accountId,
    account.providerId
  ).catch((e) => {
    logger.error(
      "Better auth was unable to query your database.\nError: ",
      e
    );
    const errorURL = c.context.options.onAPIError?.errorURL || `${c.context.baseURL}/error`;
    throw c.redirect(`${errorURL}?error=internal_server_error`);
  });
  let user = dbUser?.user;
  let isRegister = !user;
  if (dbUser) {
    const hasBeenLinked = dbUser.accounts.find(
      (a) => a.providerId === account.providerId && a.accountId === account.accountId
    );
    if (!hasBeenLinked) {
      const trustedProviders = c.context.options.account?.accountLinking?.trustedProviders;
      const isTrustedProvider = trustedProviders?.includes(
        account.providerId
      );
      if (!isTrustedProvider && !userInfo.emailVerified || c.context.options.account?.accountLinking?.enabled === false) {
        if (isDevelopment) {
          logger.warn(
            `User already exist but account isn't linked to ${account.providerId}. To read more about how account linking works in Better Auth see https://www.better-auth.com/docs/concepts/users-accounts#account-linking.`
          );
        }
        return {
          error: "account not linked",
          data: null
        };
      }
      try {
        await c.context.internalAdapter.linkAccount(
          {
            providerId: account.providerId,
            accountId: userInfo.id.toString(),
            userId: dbUser.user.id,
            accessToken: await setTokenUtil(account.accessToken, c.context),
            refreshToken: await setTokenUtil(account.refreshToken, c.context),
            idToken: account.idToken,
            accessTokenExpiresAt: account.accessTokenExpiresAt,
            refreshTokenExpiresAt: account.refreshTokenExpiresAt,
            scope: account.scope
          },
          c
        );
      } catch (e) {
        logger.error("Unable to link account", e);
        return {
          error: "unable to link account",
          data: null
        };
      }
      if (userInfo.emailVerified && !dbUser.user.emailVerified && userInfo.email.toLowerCase() === dbUser.user.email) {
        await c.context.internalAdapter.updateUser(dbUser.user.id, {
          emailVerified: true
        });
      }
    } else {
      if (c.context.options.account?.updateAccountOnSignIn !== false) {
        const updateData = Object.fromEntries(
          Object.entries({
            idToken: account.idToken,
            accessToken: await setTokenUtil(account.accessToken, c.context),
            refreshToken: await setTokenUtil(account.refreshToken, c.context),
            accessTokenExpiresAt: account.accessTokenExpiresAt,
            refreshTokenExpiresAt: account.refreshTokenExpiresAt,
            scope: account.scope
          }).filter(([_, value]) => value !== void 0)
        );
        if (Object.keys(updateData).length > 0) {
          await c.context.internalAdapter.updateAccount(
            hasBeenLinked.id,
            updateData,
            c
          );
        }
      }
      if (userInfo.emailVerified && !dbUser.user.emailVerified && userInfo.email.toLowerCase() === dbUser.user.email) {
        await c.context.internalAdapter.updateUser(dbUser.user.id, {
          emailVerified: true
        });
      }
    }
    if (overrideUserInfo) {
      const { id: _, ...restUserInfo } = userInfo;
      await c.context.internalAdapter.updateUser(dbUser.user.id, {
        ...restUserInfo,
        email: userInfo.email.toLowerCase(),
        emailVerified: userInfo.email.toLowerCase() === dbUser.user.email ? dbUser.user.emailVerified || userInfo.emailVerified : userInfo.emailVerified
      });
    }
  } else {
    if (disableSignUp) {
      return {
        error: "signup disabled",
        data: null,
        isRegister: false
      };
    }
    try {
      const { id: _, ...restUserInfo } = userInfo;
      user = await c.context.internalAdapter.createOAuthUser(
        {
          ...restUserInfo,
          email: userInfo.email.toLowerCase()
        },
        {
          accessToken: await setTokenUtil(account.accessToken, c.context),
          refreshToken: await setTokenUtil(account.refreshToken, c.context),
          idToken: account.idToken,
          accessTokenExpiresAt: account.accessTokenExpiresAt,
          refreshTokenExpiresAt: account.refreshTokenExpiresAt,
          scope: account.scope,
          providerId: account.providerId,
          accountId: userInfo.id.toString()
        },
        c
      ).then((res) => res?.user);
      if (!userInfo.emailVerified && user && c.context.options.emailVerification?.sendOnSignUp) {
        const token = await createEmailVerificationToken(
          c.context.secret,
          user.email,
          void 0,
          c.context.options.emailVerification?.expiresIn
        );
        const url = `${c.context.baseURL}/verify-email?token=${token}&callbackURL=${callbackURL}`;
        await c.context.options.emailVerification?.sendVerificationEmail?.(
          {
            user,
            url,
            token
          },
          c.request
        );
      }
    } catch (e) {
      logger.error(e);
      if (e instanceof APIError) {
        return {
          error: e.message,
          data: null,
          isRegister: false
        };
      }
      return {
        error: "unable to create user",
        data: null,
        isRegister: false
      };
    }
  }
  if (!user) {
    return {
      error: "unable to create user",
      data: null,
      isRegister: false
    };
  }
  const session = await c.context.internalAdapter.createSession(user.id, c);
  if (!session) {
    return {
      error: "unable to create session",
      data: null,
      isRegister: false
    };
  }
  return {
    data: {
      session,
      user
    },
    error: null,
    isRegister
  };
}
__name(handleOAuthUserInfo, "handleOAuthUserInfo");
async function createAuthorizationURL({
  id,
  options,
  authorizationEndpoint,
  state,
  codeVerifier,
  scopes,
  claims,
  redirectURI,
  duration: duration3,
  prompt,
  accessType,
  responseType,
  display,
  loginHint,
  hd,
  responseMode,
  additionalParams,
  scopeJoiner
}) {
  const url = new URL(authorizationEndpoint);
  url.searchParams.set("response_type", responseType || "code");
  const primaryClientId = Array.isArray(options.clientId) ? options.clientId[0] : options.clientId;
  url.searchParams.set("client_id", primaryClientId);
  url.searchParams.set("state", state);
  url.searchParams.set("scope", scopes.join(scopeJoiner || " "));
  url.searchParams.set("redirect_uri", options.redirectURI || redirectURI);
  duration3 && url.searchParams.set("duration", duration3);
  display && url.searchParams.set("display", display);
  loginHint && url.searchParams.set("login_hint", loginHint);
  prompt && url.searchParams.set("prompt", prompt);
  hd && url.searchParams.set("hd", hd);
  accessType && url.searchParams.set("access_type", accessType);
  responseMode && url.searchParams.set("response_mode", responseMode);
  if (codeVerifier) {
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("code_challenge", codeChallenge);
  }
  if (claims) {
    const claimsObj = claims.reduce(
      (acc, claim) => {
        acc[claim] = null;
        return acc;
      },
      {}
    );
    url.searchParams.set(
      "claims",
      JSON.stringify({
        id_token: { email: null, email_verified: null, ...claimsObj }
      })
    );
  }
  if (additionalParams) {
    Object.entries(additionalParams).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
  }
  return url;
}
__name(createAuthorizationURL, "createAuthorizationURL");
function createAuthorizationCodeRequest({
  code,
  codeVerifier,
  redirectURI,
  options,
  authentication,
  deviceId,
  headers,
  additionalParams = {},
  resource
}) {
  const body = new URLSearchParams();
  const requestHeaders = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
    "user-agent": "better-auth",
    ...headers
  };
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  codeVerifier && body.set("code_verifier", codeVerifier);
  options.clientKey && body.set("client_key", options.clientKey);
  deviceId && body.set("device_id", deviceId);
  body.set("redirect_uri", options.redirectURI || redirectURI);
  if (resource) {
    if (typeof resource === "string") {
      body.append("resource", resource);
    } else {
      for (const _resource of resource) {
        body.append("resource", _resource);
      }
    }
  }
  if (authentication === "basic") {
    const primaryClientId = Array.isArray(options.clientId) ? options.clientId[0] : options.clientId;
    const encodedCredentials = base642.encode(
      `${primaryClientId}:${options.clientSecret ?? ""}`
    );
    requestHeaders["authorization"] = `Basic ${encodedCredentials}`;
  } else {
    const primaryClientId = Array.isArray(options.clientId) ? options.clientId[0] : options.clientId;
    body.set("client_id", primaryClientId);
    if (options.clientSecret) {
      body.set("client_secret", options.clientSecret);
    }
  }
  for (const [key, value] of Object.entries(additionalParams)) {
    if (!body.has(key)) body.append(key, value);
  }
  return {
    body,
    headers: requestHeaders
  };
}
__name(createAuthorizationCodeRequest, "createAuthorizationCodeRequest");
async function validateAuthorizationCode({
  code,
  codeVerifier,
  redirectURI,
  options,
  tokenEndpoint,
  authentication,
  deviceId,
  headers,
  additionalParams = {},
  resource
}) {
  const { body, headers: requestHeaders } = createAuthorizationCodeRequest({
    code,
    codeVerifier,
    redirectURI,
    options,
    authentication,
    deviceId,
    headers,
    additionalParams,
    resource
  });
  const { data, error: error3 } = await betterFetch(tokenEndpoint, {
    method: "POST",
    body,
    headers: requestHeaders
  });
  if (error3) {
    throw error3;
  }
  const tokens = getOAuth2Tokens(data);
  return tokens;
}
__name(validateAuthorizationCode, "validateAuthorizationCode");
function createRefreshAccessTokenRequest({
  refreshToken: refreshToken2,
  options,
  authentication,
  extraParams,
  resource
}) {
  const body = new URLSearchParams();
  const headers = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json"
  };
  body.set("grant_type", "refresh_token");
  body.set("refresh_token", refreshToken2);
  if (authentication === "basic") {
    const primaryClientId = Array.isArray(options.clientId) ? options.clientId[0] : options.clientId;
    if (primaryClientId) {
      headers["authorization"] = "Basic " + base642.encode(`${primaryClientId}:${options.clientSecret ?? ""}`);
    } else {
      headers["authorization"] = "Basic " + base642.encode(`:${options.clientSecret ?? ""}`);
    }
  } else {
    const primaryClientId = Array.isArray(options.clientId) ? options.clientId[0] : options.clientId;
    body.set("client_id", primaryClientId);
    if (options.clientSecret) {
      body.set("client_secret", options.clientSecret);
    }
  }
  if (resource) {
    if (typeof resource === "string") {
      body.append("resource", resource);
    } else {
      for (const _resource of resource) {
        body.append("resource", _resource);
      }
    }
  }
  if (extraParams) {
    for (const [key, value] of Object.entries(extraParams)) {
      body.set(key, value);
    }
  }
  return {
    body,
    headers
  };
}
__name(createRefreshAccessTokenRequest, "createRefreshAccessTokenRequest");
async function refreshAccessToken({
  refreshToken: refreshToken2,
  options,
  tokenEndpoint,
  authentication,
  extraParams
}) {
  const { body, headers } = createRefreshAccessTokenRequest({
    refreshToken: refreshToken2,
    options,
    authentication,
    extraParams
  });
  const { data, error: error3 } = await betterFetch(tokenEndpoint, {
    method: "POST",
    body,
    headers
  });
  if (error3) {
    throw error3;
  }
  const tokens = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    tokenType: data.token_type,
    scopes: data.scope?.split(" "),
    idToken: data.id_token
  };
  if (data.expires_in) {
    const now = /* @__PURE__ */ new Date();
    tokens.accessTokenExpiresAt = new Date(
      now.getTime() + data.expires_in * 1e3
    );
  }
  return tokens;
}
__name(refreshAccessToken, "refreshAccessToken");
var apple = /* @__PURE__ */ __name((options) => {
  const tokenEndpoint = "https://appleid.apple.com/auth/token";
  return {
    id: "apple",
    name: "Apple",
    async createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scope = options.disableDefaultScope ? [] : ["email", "name"];
      options.scope && _scope.push(...options.scope);
      scopes && _scope.push(...scopes);
      const url = await createAuthorizationURL({
        id: "apple",
        options,
        authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
        scopes: _scope,
        state,
        redirectURI,
        responseMode: "form_post",
        responseType: "code id_token"
      });
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      const decodedHeader = decodeProtectedHeader(token);
      const { kid, alg: jwtAlg } = decodedHeader;
      if (!kid || !jwtAlg) return false;
      const publicKey = await getApplePublicKey(kid);
      const { payload: jwtClaims } = await jwtVerify(token, publicKey, {
        algorithms: [jwtAlg],
        issuer: "https://appleid.apple.com",
        audience: options.audience && options.audience.length ? options.audience : options.appBundleIdentifier ? options.appBundleIdentifier : options.clientId,
        maxTokenAge: "1h"
      });
      ["email_verified", "is_private_email"].forEach((field) => {
        if (jwtClaims[field] !== void 0) {
          jwtClaims[field] = Boolean(jwtClaims[field]);
        }
      });
      if (nonce && jwtClaims.nonce !== nonce) {
        return false;
      }
      return !!jwtClaims;
    },
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://appleid.apple.com/auth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (!token.idToken) {
        return null;
      }
      const profile = decodeJwt(token.idToken);
      if (!profile) {
        return null;
      }
      const name = token.user ? `${token.user.name?.firstName} ${token.user.name?.lastName}` : profile.name || profile.email;
      const emailVerified = typeof profile.email_verified === "boolean" ? profile.email_verified : profile.email_verified === "true";
      const enrichedProfile = {
        ...profile,
        name
      };
      const userMap = await options.mapProfileToUser?.(enrichedProfile);
      return {
        user: {
          id: profile.sub,
          name: enrichedProfile.name,
          emailVerified,
          email: profile.email,
          ...userMap
        },
        data: enrichedProfile
      };
    },
    options
  };
}, "apple");
var getApplePublicKey = /* @__PURE__ */ __name(async (kid) => {
  const APPLE_BASE_URL = "https://appleid.apple.com";
  const JWKS_APPLE_URI = "/auth/keys";
  const { data } = await betterFetch(`${APPLE_BASE_URL}${JWKS_APPLE_URI}`);
  if (!data?.keys) {
    throw new APIError("BAD_REQUEST", {
      message: "Keys not found"
    });
  }
  const jwk = data.keys.find((key) => key.kid === kid);
  if (!jwk) {
    throw new Error(`JWK with kid ${kid} not found`);
  }
  return await importJWK(jwk, jwk.alg);
}, "getApplePublicKey");
var atlassian = /* @__PURE__ */ __name((options) => {
  return {
    id: "atlassian",
    name: "Atlassian",
    async createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      if (!options.clientId || !options.clientSecret) {
        logger.error("Client Id and Secret are required for Atlassian");
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      if (!codeVerifier) {
        throw new BetterAuthError("codeVerifier is required for Atlassian");
      }
      const _scopes = options.disableDefaultScope ? [] : ["read:jira-user", "offline_access"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "atlassian",
        options,
        authorizationEndpoint: "https://auth.atlassian.com/authorize",
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI,
        additionalParams: {
          audience: "api.atlassian.com"
        },
        prompt: options.prompt
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint: "https://auth.atlassian.com/oauth/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://auth.atlassian.com/oauth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (!token.accessToken) {
        return null;
      }
      try {
        const { data: profile } = await betterFetch("https://api.atlassian.com/me", {
          headers: { Authorization: `Bearer ${token.accessToken}` }
        });
        if (!profile) return null;
        const userMap = await options.mapProfileToUser?.(profile);
        return {
          user: {
            id: profile.account_id,
            name: profile.name,
            email: profile.email,
            image: profile.picture,
            emailVerified: false,
            ...userMap
          },
          data: profile
        };
      } catch (error3) {
        logger.error("Failed to fetch user info from Figma:", error3);
        return null;
      }
    },
    options
  };
}, "atlassian");
var cognito = /* @__PURE__ */ __name((options) => {
  if (!options.domain || !options.region || !options.userPoolId) {
    logger.error(
      "Domain, region and userPoolId are required for Amazon Cognito. Make sure to provide them in the options."
    );
    throw new BetterAuthError("DOMAIN_AND_REGION_REQUIRED");
  }
  const cleanDomain = options.domain.replace(/^https?:\/\//, "");
  const authorizationEndpoint = `https://${cleanDomain}/oauth2/authorize`;
  const tokenEndpoint = `https://${cleanDomain}/oauth2/token`;
  const userInfoEndpoint = `https://${cleanDomain}/oauth2/userinfo`;
  return {
    id: "cognito",
    name: "Cognito",
    async createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      if (!options.clientId) {
        logger.error(
          "ClientId is required for Amazon Cognito. Make sure to provide them in the options."
        );
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      if (options.requireClientSecret && !options.clientSecret) {
        logger.error(
          "Client Secret is required when requireClientSecret is true. Make sure to provide it in the options."
        );
        throw new BetterAuthError("CLIENT_SECRET_REQUIRED");
      }
      const _scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      const url = await createAuthorizationURL({
        id: "cognito",
        options: {
          ...options
        },
        authorizationEndpoint,
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI,
        prompt: options.prompt
      });
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      try {
        const decodedHeader = decodeProtectedHeader(token);
        const { kid, alg: jwtAlg } = decodedHeader;
        if (!kid || !jwtAlg) return false;
        const publicKey = await getCognitoPublicKey(
          kid,
          options.region,
          options.userPoolId
        );
        const expectedIssuer = `https://cognito-idp.${options.region}.amazonaws.com/${options.userPoolId}`;
        const { payload: jwtClaims } = await jwtVerify(token, publicKey, {
          algorithms: [jwtAlg],
          issuer: expectedIssuer,
          audience: options.clientId,
          maxTokenAge: "1h"
        });
        if (nonce && jwtClaims.nonce !== nonce) {
          return false;
        }
        return true;
      } catch (error3) {
        logger.error("Failed to verify ID token:", error3);
        return false;
      }
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (token.idToken) {
        try {
          const profile = decodeJwt(token.idToken);
          if (!profile) {
            return null;
          }
          const name = profile.name || profile.given_name || profile.username || profile.email;
          const enrichedProfile = {
            ...profile,
            name
          };
          const userMap = await options.mapProfileToUser?.(enrichedProfile);
          return {
            user: {
              id: profile.sub,
              name: enrichedProfile.name,
              email: profile.email,
              image: profile.picture,
              emailVerified: profile.email_verified,
              ...userMap
            },
            data: enrichedProfile
          };
        } catch (error3) {
          logger.error("Failed to decode ID token:", error3);
        }
      }
      if (token.accessToken) {
        try {
          const { data: userInfo } = await betterFetch(
            userInfoEndpoint,
            {
              headers: {
                Authorization: `Bearer ${token.accessToken}`
              }
            }
          );
          if (userInfo) {
            const userMap = await options.mapProfileToUser?.(userInfo);
            return {
              user: {
                id: userInfo.sub,
                name: userInfo.name || userInfo.given_name || userInfo.username,
                email: userInfo.email,
                image: userInfo.picture,
                emailVerified: userInfo.email_verified,
                ...userMap
              },
              data: userInfo
            };
          }
        } catch (error3) {
          logger.error("Failed to fetch user info from Cognito:", error3);
        }
      }
      return null;
    },
    options
  };
}, "cognito");
var getCognitoPublicKey = /* @__PURE__ */ __name(async (kid, region, userPoolId) => {
  const COGNITO_JWKS_URI = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
  try {
    const { data } = await betterFetch(COGNITO_JWKS_URI);
    if (!data?.keys) {
      throw new APIError("BAD_REQUEST", {
        message: "Keys not found"
      });
    }
    const jwk = data.keys.find((key) => key.kid === kid);
    if (!jwk) {
      throw new Error(`JWK with kid ${kid} not found`);
    }
    return await importJWK(jwk, jwk.alg);
  } catch (error3) {
    logger.error("Failed to fetch Cognito public key:", error3);
    throw error3;
  }
}, "getCognitoPublicKey");
var discord = /* @__PURE__ */ __name((options) => {
  return {
    id: "discord",
    name: "Discord",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["identify", "email"];
      scopes && _scopes.push(...scopes);
      options.scope && _scopes.push(...options.scope);
      const hasBotScope = _scopes.includes("bot");
      const permissionsParam = hasBotScope && options.permissions !== void 0 ? `&permissions=${options.permissions}` : "";
      return new URL(
        `https://discord.com/api/oauth2/authorize?scope=${_scopes.join(
          "+"
        )}&response_type=code&client_id=${options.clientId}&redirect_uri=${encodeURIComponent(
          options.redirectURI || redirectURI
        )}&state=${state}&prompt=${options.prompt || "none"}${permissionsParam}`
      );
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://discord.com/api/oauth2/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://discord.com/api/oauth2/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://discord.com/api/users/@me",
        {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      if (profile.avatar === null) {
        const defaultAvatarNumber = profile.discriminator === "0" ? Number(BigInt(profile.id) >> BigInt(22)) % 6 : parseInt(profile.discriminator) % 5;
        profile.image_url = `https://cdn.discordapp.com/embed/avatars/${defaultAvatarNumber}.png`;
      } else {
        const format2 = profile.avatar.startsWith("a_") ? "gif" : "png";
        profile.image_url = `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.${format2}`;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.global_name || profile.username || "",
          email: profile.email,
          emailVerified: profile.verified,
          image: profile.image_url,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "discord");
var facebook = /* @__PURE__ */ __name((options) => {
  return {
    id: "facebook",
    name: "Facebook",
    async createAuthorizationURL({ state, scopes, redirectURI, loginHint }) {
      const _scopes = options.disableDefaultScope ? [] : ["email", "public_profile"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return await createAuthorizationURL({
        id: "facebook",
        options,
        authorizationEndpoint: "https://www.facebook.com/v21.0/dialog/oauth",
        scopes: _scopes,
        state,
        redirectURI,
        loginHint,
        additionalParams: options.configId ? {
          config_id: options.configId
        } : {}
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://graph.facebook.com/oauth/access_token"
      });
    }, "validateAuthorizationCode"),
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      if (token.split(".").length === 3) {
        try {
          const { payload: jwtClaims } = await jwtVerify(
            token,
            createRemoteJWKSet(
              // https://developers.facebook.com/docs/facebook-login/limited-login/token/#jwks
              new URL(
                "https://limited.facebook.com/.well-known/oauth/openid/jwks/"
              )
            ),
            {
              algorithms: ["RS256"],
              audience: options.clientId,
              issuer: "https://www.facebook.com"
            }
          );
          if (nonce && jwtClaims.nonce !== nonce) {
            return false;
          }
          return !!jwtClaims;
        } catch (error3) {
          return false;
        }
      }
      return true;
    },
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://graph.facebook.com/v18.0/oauth/access_token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (token.idToken && token.idToken.split(".").length === 3) {
        const profile2 = decodeJwt(token.idToken);
        const user = {
          id: profile2.sub,
          name: profile2.name,
          email: profile2.email,
          picture: {
            data: {
              url: profile2.picture,
              height: 100,
              width: 100,
              is_silhouette: false
            }
          }
        };
        const userMap2 = await options.mapProfileToUser?.({
          ...user,
          email_verified: true
        });
        return {
          user: {
            ...user,
            emailVerified: true,
            ...userMap2
          },
          data: profile2
        };
      }
      const fields = [
        "id",
        "name",
        "email",
        "picture",
        ...options?.fields || []
      ];
      const { data: profile, error: error3 } = await betterFetch(
        "https://graph.facebook.com/me?fields=" + fields.join(","),
        {
          auth: {
            type: "Bearer",
            token: token.accessToken
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.name,
          email: profile.email,
          image: profile.picture.data.url,
          emailVerified: profile.email_verified,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "facebook");
var figma = /* @__PURE__ */ __name((options) => {
  return {
    id: "figma",
    name: "Figma",
    async createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      if (!options.clientId || !options.clientSecret) {
        logger.error(
          "Client Id and Client Secret are required for Figma. Make sure to provide them in the options."
        );
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      if (!codeVerifier) {
        throw new BetterAuthError("codeVerifier is required for Figma");
      }
      const _scopes = options.disableDefaultScope ? [] : ["file_read"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      const url = await createAuthorizationURL({
        id: "figma",
        options,
        authorizationEndpoint: "https://www.figma.com/oauth",
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI
      });
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint: "https://www.figma.com/api/oauth/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://www.figma.com/api/oauth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      try {
        const { data: profile } = await betterFetch(
          "https://api.figma.com/v1/me",
          {
            headers: {
              Authorization: `Bearer ${token.accessToken}`
            }
          }
        );
        if (!profile) {
          logger.error("Failed to fetch user from Figma");
          return null;
        }
        const userMap = await options.mapProfileToUser?.(profile);
        return {
          user: {
            id: profile.id,
            name: profile.handle,
            email: profile.email,
            image: profile.img_url,
            emailVerified: !!profile.email,
            ...userMap
          },
          data: profile
        };
      } catch (error3) {
        logger.error("Failed to fetch user info from Figma:", error3);
        return null;
      }
    },
    options
  };
}, "figma");
var github = /* @__PURE__ */ __name((options) => {
  const tokenEndpoint = "https://github.com/login/oauth/access_token";
  return {
    id: "github",
    name: "GitHub",
    createAuthorizationURL({ state, scopes, loginHint, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["read:user", "user:email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "github",
        options,
        authorizationEndpoint: "https://github.com/login/oauth/authorize",
        scopes: _scopes,
        state,
        redirectURI,
        loginHint,
        prompt: options.prompt
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://github.com/login/oauth/access_token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.github.com/user",
        {
          headers: {
            "User-Agent": "better-auth",
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const { data: emails } = await betterFetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${token.accessToken}`,
          "User-Agent": "better-auth"
        }
      });
      if (!profile.email && emails) {
        profile.email = (emails.find((e) => e.primary) ?? emails[0])?.email;
      }
      const emailVerified = emails?.find((e) => e.email === profile.email)?.verified ?? false;
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.name || profile.login,
          email: profile.email,
          image: profile.avatar_url,
          emailVerified,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "github");
var google = /* @__PURE__ */ __name((options) => {
  return {
    id: "google",
    name: "Google",
    async createAuthorizationURL({
      state,
      scopes,
      codeVerifier,
      redirectURI,
      loginHint,
      display
    }) {
      if (!options.clientId || !options.clientSecret) {
        logger.error(
          "Client Id and Client Secret is required for Google. Make sure to provide them in the options."
        );
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      if (!codeVerifier) {
        throw new BetterAuthError("codeVerifier is required for Google");
      }
      const _scopes = options.disableDefaultScope ? [] : ["email", "profile", "openid"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      const url = await createAuthorizationURL({
        id: "google",
        options,
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/auth",
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI,
        prompt: options.prompt,
        accessType: options.accessType,
        display: display || options.display,
        loginHint,
        hd: options.hd,
        additionalParams: {
          include_granted_scopes: "true"
        }
      });
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint: "https://oauth2.googleapis.com/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://www.googleapis.com/oauth2/v4/token"
      });
    },
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      const googlePublicKeyUrl = `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${token}`;
      const { data: tokenInfo } = await betterFetch(googlePublicKeyUrl);
      if (!tokenInfo) {
        return false;
      }
      const isValid = tokenInfo.aud === options.clientId && (tokenInfo.iss === "https://accounts.google.com" || tokenInfo.iss === "accounts.google.com");
      return isValid;
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (!token.idToken) {
        return null;
      }
      const user = decodeJwt(token.idToken);
      const userMap = await options.mapProfileToUser?.(user);
      return {
        user: {
          id: user.sub,
          name: user.name,
          email: user.email,
          image: user.picture,
          emailVerified: user.email_verified,
          ...userMap
        },
        data: user
      };
    },
    options
  };
}, "google");
var kick = /* @__PURE__ */ __name((options) => {
  return {
    id: "kick",
    name: "Kick",
    createAuthorizationURL({ state, scopes, redirectURI, codeVerifier }) {
      const _scopes = options.disableDefaultScope ? [] : ["user:read"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "kick",
        redirectURI,
        options,
        authorizationEndpoint: "https://id.kick.com/oauth/authorize",
        scopes: _scopes,
        codeVerifier,
        state
      });
    },
    async validateAuthorizationCode({ code, redirectURI, codeVerifier }) {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://id.kick.com/oauth/token",
        codeVerifier
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data, error: error3 } = await betterFetch("https://api.kick.com/public/v1/users", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token.accessToken}`
        }
      });
      if (error3) {
        return null;
      }
      const profile = data.data[0];
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.user_id,
          name: profile.name,
          email: profile.email,
          image: profile.profile_picture,
          emailVerified: true,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "kick");
var huggingface = /* @__PURE__ */ __name((options) => {
  return {
    id: "huggingface",
    name: "Hugging Face",
    createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "huggingface",
        options,
        authorizationEndpoint: "https://huggingface.co/oauth/authorize",
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint: "https://huggingface.co/oauth/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://huggingface.co/oauth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://huggingface.co/oauth/userinfo",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.sub,
          name: profile.name || profile.preferred_username,
          email: profile.email,
          image: profile.picture,
          emailVerified: profile.email_verified ?? false,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "huggingface");
var microsoft = /* @__PURE__ */ __name((options) => {
  const tenant = options.tenantId || "common";
  const authority = options.authority || "https://login.microsoftonline.com";
  const authorizationEndpoint = `${authority}/${tenant}/oauth2/v2.0/authorize`;
  const tokenEndpoint = `${authority}/${tenant}/oauth2/v2.0/token`;
  return {
    id: "microsoft",
    name: "Microsoft EntraID",
    createAuthorizationURL(data) {
      const scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email", "User.Read", "offline_access"];
      options.scope && scopes.push(...options.scope);
      data.scopes && scopes.push(...data.scopes);
      return createAuthorizationURL({
        id: "microsoft",
        options,
        authorizationEndpoint,
        state: data.state,
        codeVerifier: data.codeVerifier,
        scopes,
        redirectURI: data.redirectURI,
        prompt: options.prompt,
        loginHint: data.loginHint
      });
    },
    validateAuthorizationCode({ code, codeVerifier, redirectURI }) {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (!token.idToken) {
        return null;
      }
      const user = decodeJwt(token.idToken);
      const profilePhotoSize = options.profilePhotoSize || 48;
      await betterFetch(
        `https://graph.microsoft.com/v1.0/me/photos/${profilePhotoSize}x${profilePhotoSize}/$value`,
        {
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          },
          async onResponse(context) {
            if (options.disableProfilePhoto || !context.response.ok) {
              return;
            }
            try {
              const response = context.response.clone();
              const pictureBuffer = await response.arrayBuffer();
              const pictureBase64 = base642.encode(pictureBuffer);
              user.picture = `data:image/jpeg;base64, ${pictureBase64}`;
            } catch (e) {
              logger.error(
                e && typeof e === "object" && "name" in e ? e.name : "",
                e
              );
            }
          }
        }
      );
      const userMap = await options.mapProfileToUser?.(user);
      return {
        user: {
          id: user.sub,
          name: user.name,
          email: user.email,
          image: user.picture,
          emailVerified: true,
          ...userMap
        },
        data: user
      };
    },
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      const scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email", "User.Read", "offline_access"];
      options.scope && scopes.push(...options.scope);
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientSecret: options.clientSecret
        },
        extraParams: {
          scope: scopes.join(" ")
          // Include the scopes in request to microsoft
        },
        tokenEndpoint
      });
    },
    options
  };
}, "microsoft");
var slack = /* @__PURE__ */ __name((options) => {
  return {
    id: "slack",
    name: "Slack",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email"];
      scopes && _scopes.push(...scopes);
      options.scope && _scopes.push(...options.scope);
      const url = new URL("https://slack.com/openid/connect/authorize");
      url.searchParams.set("scope", _scopes.join(" "));
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", options.redirectURI || redirectURI);
      url.searchParams.set("state", state);
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://slack.com/api/openid.connect.token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://slack.com/api/openid.connect.token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://slack.com/api/openid.connect.userInfo",
        {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile["https://slack.com/user_id"],
          name: profile.name || "",
          email: profile.email,
          emailVerified: profile.email_verified,
          image: profile.picture || profile["https://slack.com/user_image_512"],
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "slack");
var notion = /* @__PURE__ */ __name((options) => {
  const tokenEndpoint = "https://api.notion.com/v1/oauth/token";
  return {
    id: "notion",
    name: "Notion",
    createAuthorizationURL({ state, scopes, loginHint, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : [];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "notion",
        options,
        authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize",
        scopes: _scopes,
        state,
        redirectURI,
        loginHint,
        additionalParams: {
          owner: "user"
        }
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint,
        authentication: "basic"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch("https://api.notion.com/v1/users/me", {
        headers: {
          Authorization: `Bearer ${token.accessToken}`,
          "Notion-Version": "2022-06-28"
        }
      });
      if (error3 || !profile) {
        return null;
      }
      const userProfile = profile.bot?.owner?.user;
      if (!userProfile) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(userProfile);
      return {
        user: {
          id: userProfile.id,
          name: userProfile.name || "Notion User",
          email: userProfile.person?.email || null,
          image: userProfile.avatar_url,
          emailVerified: !!userProfile.person?.email,
          ...userMap
        },
        data: userProfile
      };
    },
    options
  };
}, "notion");
var spotify = /* @__PURE__ */ __name((options) => {
  return {
    id: "spotify",
    name: "Spotify",
    createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["user-read-email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "spotify",
        options,
        authorizationEndpoint: "https://accounts.spotify.com/authorize",
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint: "https://accounts.spotify.com/api/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://accounts.spotify.com/api/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.spotify.com/v1/me",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.display_name,
          email: profile.email,
          image: profile.images[0]?.url,
          emailVerified: false,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "spotify");
var twitch = /* @__PURE__ */ __name((options) => {
  return {
    id: "twitch",
    name: "Twitch",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["user:read:email", "openid"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "twitch",
        redirectURI,
        options,
        authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
        scopes: _scopes,
        state,
        claims: options.claims || [
          "email",
          "email_verified",
          "preferred_username",
          "picture"
        ]
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://id.twitch.tv/oauth2/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://id.twitch.tv/oauth2/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const idToken = token.idToken;
      if (!idToken) {
        logger.error("No idToken found in token");
        return null;
      }
      const profile = decodeJwt(idToken);
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.sub,
          name: profile.preferred_username,
          email: profile.email,
          image: profile.picture,
          emailVerified: profile.email_verified,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "twitch");
var twitter = /* @__PURE__ */ __name((options) => {
  return {
    id: "twitter",
    name: "Twitter",
    createAuthorizationURL(data) {
      const _scopes = options.disableDefaultScope ? [] : ["users.read", "tweet.read", "offline.access", "users.email"];
      options.scope && _scopes.push(...options.scope);
      data.scopes && _scopes.push(...data.scopes);
      return createAuthorizationURL({
        id: "twitter",
        options,
        authorizationEndpoint: "https://x.com/i/oauth2/authorize",
        scopes: _scopes,
        state: data.state,
        codeVerifier: data.codeVerifier,
        redirectURI: data.redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        authentication: "basic",
        redirectURI,
        options,
        tokenEndpoint: "https://api.x.com/2/oauth2/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        authentication: "basic",
        tokenEndpoint: "https://api.x.com/2/oauth2/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: profileError } = await betterFetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (profileError) {
        return null;
      }
      const { data: emailData, error: emailError } = await betterFetch("https://api.x.com/2/users/me?user.fields=confirmed_email", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token.accessToken}`
        }
      });
      let emailVerified = false;
      if (!emailError && emailData?.data?.confirmed_email) {
        profile.data.email = emailData.data.confirmed_email;
        emailVerified = true;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.data.id,
          name: profile.data.name,
          email: profile.data.email || profile.data.username || null,
          image: profile.data.profile_image_url,
          emailVerified,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "twitter");
var dropbox = /* @__PURE__ */ __name((options) => {
  const tokenEndpoint = "https://api.dropboxapi.com/oauth2/token";
  return {
    id: "dropbox",
    name: "Dropbox",
    createAuthorizationURL: /* @__PURE__ */ __name(async ({
      state,
      scopes,
      codeVerifier,
      redirectURI
    }) => {
      const _scopes = options.disableDefaultScope ? [] : ["account_info.read"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      const additionalParams = {};
      if (options.accessType) {
        additionalParams.token_access_type = options.accessType;
      }
      return await createAuthorizationURL({
        id: "dropbox",
        options,
        authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
        scopes: _scopes,
        state,
        redirectURI,
        codeVerifier,
        additionalParams
      });
    }, "createAuthorizationURL"),
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return await validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://api.dropbox.com/oauth2/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.dropboxapi.com/2/users/get_current_account",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.account_id,
          name: profile.name?.display_name,
          email: profile.email,
          emailVerified: profile.email_verified || false,
          image: profile.profile_photo_url,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "dropbox");
var linear = /* @__PURE__ */ __name((options) => {
  const tokenEndpoint = "https://api.linear.app/oauth/token";
  return {
    id: "linear",
    name: "Linear",
    createAuthorizationURL({ state, scopes, loginHint, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["read"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "linear",
        options,
        authorizationEndpoint: "https://linear.app/oauth/authorize",
        scopes: _scopes,
        state,
        redirectURI,
        loginHint
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.linear.app/graphql",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token.accessToken}`
          },
          body: JSON.stringify({
            query: `
							query {
								viewer {
									id
									name
									email
									avatarUrl
									active
									createdAt
									updatedAt
								}
							}
						`
          })
        }
      );
      if (error3 || !profile?.data?.viewer) {
        return null;
      }
      const userData = profile.data.viewer;
      const userMap = await options.mapProfileToUser?.(userData);
      return {
        user: {
          id: profile.data.viewer.id,
          name: profile.data.viewer.name,
          email: profile.data.viewer.email,
          image: profile.data.viewer.avatarUrl,
          emailVerified: true,
          ...userMap
        },
        data: userData
      };
    },
    options
  };
}, "linear");
var linkedin = /* @__PURE__ */ __name((options) => {
  const authorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
  const tokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
  return {
    id: "linkedin",
    name: "Linkedin",
    createAuthorizationURL: /* @__PURE__ */ __name(async ({
      state,
      scopes,
      redirectURI,
      loginHint
    }) => {
      const _scopes = options.disableDefaultScope ? [] : ["profile", "email", "openid"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return await createAuthorizationURL({
        id: "linkedin",
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        loginHint,
        redirectURI
      });
    }, "createAuthorizationURL"),
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return await validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.linkedin.com/v2/userinfo",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          emailVerified: profile.email_verified || false,
          image: profile.picture,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "linkedin");
var cleanDoubleSlashes = /* @__PURE__ */ __name((input = "") => {
  return input.split("://").map((str) => str.replace(/\/{2,}/g, "/")).join("://");
}, "cleanDoubleSlashes");
var issuerToEndpoints = /* @__PURE__ */ __name((issuer) => {
  let baseUrl = issuer || "https://gitlab.com";
  return {
    authorizationEndpoint: cleanDoubleSlashes(`${baseUrl}/oauth/authorize`),
    tokenEndpoint: cleanDoubleSlashes(`${baseUrl}/oauth/token`),
    userinfoEndpoint: cleanDoubleSlashes(`${baseUrl}/api/v4/user`)
  };
}, "issuerToEndpoints");
var gitlab = /* @__PURE__ */ __name((options) => {
  const { authorizationEndpoint, tokenEndpoint, userinfoEndpoint } = issuerToEndpoints(options.issuer);
  const issuerId = "gitlab";
  const issuerName = "Gitlab";
  return {
    id: issuerId,
    name: issuerName,
    createAuthorizationURL: /* @__PURE__ */ __name(async ({
      state,
      scopes,
      codeVerifier,
      loginHint,
      redirectURI
    }) => {
      const _scopes = options.disableDefaultScope ? [] : ["read_user"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return await createAuthorizationURL({
        id: issuerId,
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        redirectURI,
        codeVerifier,
        loginHint
      });
    }, "createAuthorizationURL"),
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI, codeVerifier }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        codeVerifier,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://gitlab.com/oauth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        userinfoEndpoint,
        { headers: { authorization: `Bearer ${token.accessToken}` } }
      );
      if (error3 || profile.state !== "active" || profile.locked) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.name ?? profile.username,
          email: profile.email,
          image: profile.avatar_url,
          emailVerified: true,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "gitlab");
var tiktok = /* @__PURE__ */ __name((options) => {
  return {
    id: "tiktok",
    name: "TikTok",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["user.info.profile"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return new URL(
        `https://www.tiktok.com/v2/auth/authorize?scope=${_scopes.join(
          ","
        )}&response_type=code&client_key=${options.clientKey}&redirect_uri=${encodeURIComponent(
          options.redirectURI || redirectURI
        )}&state=${state}`
      );
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI: options.redirectURI || redirectURI,
        options: {
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/",
        authentication: "post",
        extraParams: {
          client_key: options.clientKey
        }
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const fields = [
        "open_id",
        "avatar_large_url",
        "display_name",
        "username"
      ];
      const { data: profile, error: error3 } = await betterFetch(
        `https://open.tiktokapis.com/v2/user/info/?fields=${fields.join(",")}`,
        {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      return {
        user: {
          email: profile.data.user.email || profile.data.user.username,
          id: profile.data.user.open_id,
          name: profile.data.user.display_name || profile.data.user.username,
          image: profile.data.user.avatar_large_url,
          /** @note Tiktok does not provide emailVerified or even email*/
          emailVerified: profile.data.user.email ? true : false
        },
        data: profile
      };
    },
    options
  };
}, "tiktok");
var reddit = /* @__PURE__ */ __name((options) => {
  return {
    id: "reddit",
    name: "Reddit",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["identity"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "reddit",
        options,
        authorizationEndpoint: "https://www.reddit.com/api/v1/authorize",
        scopes: _scopes,
        state,
        redirectURI,
        duration: options.duration
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: options.redirectURI || redirectURI
      });
      const headers = {
        "content-type": "application/x-www-form-urlencoded",
        accept: "text/plain",
        "user-agent": "better-auth",
        Authorization: `Basic ${base642.encode(
          `${options.clientId}:${options.clientSecret}`
        )}`
      };
      const { data, error: error3 } = await betterFetch(
        "https://www.reddit.com/api/v1/access_token",
        {
          method: "POST",
          headers,
          body: body.toString()
        }
      );
      if (error3) {
        throw error3;
      }
      return getOAuth2Tokens(data);
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        authentication: "basic",
        tokenEndpoint: "https://www.reddit.com/api/v1/access_token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://oauth.reddit.com/api/v1/me",
        {
          headers: {
            Authorization: `Bearer ${token.accessToken}`,
            "User-Agent": "better-auth"
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.name,
          email: profile.oauth_client_id,
          emailVerified: profile.has_verified_email,
          image: profile.icon_img?.split("?")[0],
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "reddit");
var roblox = /* @__PURE__ */ __name((options) => {
  return {
    id: "roblox",
    name: "Roblox",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["openid", "profile"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return new URL(
        `https://apis.roblox.com/oauth/v1/authorize?scope=${_scopes.join(
          "+"
        )}&response_type=code&client_id=${options.clientId}&redirect_uri=${encodeURIComponent(
          options.redirectURI || redirectURI
        )}&state=${state}&prompt=${options.prompt || "select_account consent"}`
      );
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI: options.redirectURI || redirectURI,
        options,
        tokenEndpoint: "https://apis.roblox.com/oauth/v1/token",
        authentication: "post"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://apis.roblox.com/oauth/v1/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://apis.roblox.com/oauth/v1/userinfo",
        {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.sub,
          name: profile.nickname || profile.preferred_username || "",
          image: profile.picture,
          email: profile.preferred_username || null,
          // Roblox does not provide email
          emailVerified: true,
          ...userMap
        },
        data: {
          ...profile
        }
      };
    },
    options
  };
}, "roblox");
var salesforce = /* @__PURE__ */ __name((options) => {
  const environment = options.environment ?? "production";
  const isSandbox = environment === "sandbox";
  const authorizationEndpoint = options.loginUrl ? `https://${options.loginUrl}/services/oauth2/authorize` : isSandbox ? "https://test.salesforce.com/services/oauth2/authorize" : "https://login.salesforce.com/services/oauth2/authorize";
  const tokenEndpoint = options.loginUrl ? `https://${options.loginUrl}/services/oauth2/token` : isSandbox ? "https://test.salesforce.com/services/oauth2/token" : "https://login.salesforce.com/services/oauth2/token";
  const userInfoEndpoint = options.loginUrl ? `https://${options.loginUrl}/services/oauth2/userinfo` : isSandbox ? "https://test.salesforce.com/services/oauth2/userinfo" : "https://login.salesforce.com/services/oauth2/userinfo";
  return {
    id: "salesforce",
    name: "Salesforce",
    async createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      if (!options.clientId || !options.clientSecret) {
        logger.error(
          "Client Id and Client Secret are required for Salesforce. Make sure to provide them in the options."
        );
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      if (!codeVerifier) {
        throw new BetterAuthError("codeVerifier is required for Salesforce");
      }
      const _scopes = options.disableDefaultScope ? [] : ["openid", "email", "profile"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "salesforce",
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI: options.redirectURI || redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI: options.redirectURI || redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      try {
        const { data: user } = await betterFetch(
          userInfoEndpoint,
          {
            headers: {
              Authorization: `Bearer ${token.accessToken}`
            }
          }
        );
        if (!user) {
          logger.error("Failed to fetch user info from Salesforce");
          return null;
        }
        const userMap = await options.mapProfileToUser?.(user);
        return {
          user: {
            id: user.user_id,
            name: user.name,
            email: user.email,
            image: user.photos?.picture || user.photos?.thumbnail,
            emailVerified: user.email_verified ?? false,
            ...userMap
          },
          data: user
        };
      } catch (error3) {
        logger.error("Failed to fetch user info from Salesforce:", error3);
        return null;
      }
    },
    options
  };
}, "salesforce");
var vk = /* @__PURE__ */ __name((options) => {
  return {
    id: "vk",
    name: "VK",
    async createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["email", "phone"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      const authorizationEndpoint = "https://id.vk.com/authorize";
      return createAuthorizationURL({
        id: "vk",
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        redirectURI,
        codeVerifier
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({
      code,
      codeVerifier,
      redirectURI,
      deviceId
    }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI: options.redirectURI || redirectURI,
        options,
        deviceId,
        tokenEndpoint: "https://id.vk.com/oauth2/auth"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://id.vk.com/oauth2/auth"
      });
    },
    async getUserInfo(data) {
      if (options.getUserInfo) {
        return options.getUserInfo(data);
      }
      if (!data.accessToken) {
        return null;
      }
      const formBody = new URLSearchParams({
        access_token: data.accessToken,
        client_id: options.clientId
      }).toString();
      const { data: profile, error: error3 } = await betterFetch(
        "https://id.vk.com/oauth2/user_info",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: formBody
        }
      );
      if (error3) {
        return null;
      }
      if (!profile.user.email) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.user.user_id,
          first_name: profile.user.first_name,
          last_name: profile.user.last_name,
          email: profile.user.email,
          image: profile.user.avatar,
          /** @note VK does not provide emailVerified*/
          emailVerified: !!profile.user.email,
          birthday: profile.user.birthday,
          sex: profile.user.sex,
          name: `${profile.user.first_name} ${profile.user.last_name}`,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "vk");
var zoom = /* @__PURE__ */ __name((userOptions) => {
  const options = {
    pkce: true,
    ...userOptions
  };
  return {
    id: "zoom",
    name: "Zoom",
    createAuthorizationURL: /* @__PURE__ */ __name(async ({ state, redirectURI, codeVerifier }) => {
      const params = new URLSearchParams({
        response_type: "code",
        redirect_uri: options.redirectURI ? options.redirectURI : redirectURI,
        client_id: options.clientId,
        state
      });
      if (options.pkce) {
        const codeChallenge = await generateCodeChallenge(codeVerifier);
        params.set("code_challenge_method", "S256");
        params.set("code_challenge", codeChallenge);
      }
      const url = new URL("https://zoom.us/oauth/authorize");
      url.search = params.toString();
      return url;
    }, "createAuthorizationURL"),
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI, codeVerifier }) => {
      return validateAuthorizationCode({
        code,
        redirectURI: options.redirectURI || redirectURI,
        codeVerifier,
        options,
        tokenEndpoint: "https://zoom.us/oauth/token",
        authentication: "post"
      });
    }, "validateAuthorizationCode"),
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://api.zoom.us/v2/users/me",
        {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      return {
        user: {
          id: profile.id,
          name: profile.display_name,
          image: profile.pic_url,
          email: profile.email,
          emailVerified: Boolean(profile.verified),
          ...userMap
        },
        data: {
          ...profile
        }
      };
    }
  };
}, "zoom");
var kakao = /* @__PURE__ */ __name((options) => {
  return {
    id: "kakao",
    name: "Kakao",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["account_email", "profile_image", "profile_nickname"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "kakao",
        options,
        authorizationEndpoint: "https://kauth.kakao.com/oauth/authorize",
        scopes: _scopes,
        state,
        redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://kauth.kakao.com/oauth/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://kauth.kakao.com/oauth/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://kapi.kakao.com/v2/user/me",
        {
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3 || !profile) {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      const account = profile.kakao_account || {};
      const kakaoProfile = account.profile || {};
      const user = {
        id: String(profile.id),
        name: kakaoProfile.nickname || account.name || void 0,
        email: account.email,
        image: kakaoProfile.profile_image_url || kakaoProfile.thumbnail_image_url,
        emailVerified: !!account.is_email_valid && !!account.is_email_verified,
        ...userMap
      };
      return {
        user,
        data: profile
      };
    },
    options
  };
}, "kakao");
var naver = /* @__PURE__ */ __name((options) => {
  return {
    id: "naver",
    name: "Naver",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      const _scopes = options.disableDefaultScope ? [] : ["profile", "email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return createAuthorizationURL({
        id: "naver",
        options,
        authorizationEndpoint: "https://nid.naver.com/oauth2.0/authorize",
        scopes: _scopes,
        state,
        redirectURI
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        redirectURI,
        options,
        tokenEndpoint: "https://nid.naver.com/oauth2.0/token"
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientKey: options.clientKey,
          clientSecret: options.clientSecret
        },
        tokenEndpoint: "https://nid.naver.com/oauth2.0/token"
      });
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      const { data: profile, error: error3 } = await betterFetch(
        "https://openapi.naver.com/v1/nid/me",
        {
          headers: {
            Authorization: `Bearer ${token.accessToken}`
          }
        }
      );
      if (error3 || !profile || profile.resultcode !== "00") {
        return null;
      }
      const userMap = await options.mapProfileToUser?.(profile);
      const res = profile.response || {};
      const user = {
        id: res.id,
        name: res.name || res.nickname,
        email: res.email,
        image: res.profile_image,
        emailVerified: false,
        ...userMap
      };
      return {
        user,
        data: profile
      };
    },
    options
  };
}, "naver");
var line = /* @__PURE__ */ __name((options) => {
  const authorizationEndpoint = "https://access.line.me/oauth2/v2.1/authorize";
  const tokenEndpoint = "https://api.line.me/oauth2/v2.1/token";
  const userInfoEndpoint = "https://api.line.me/oauth2/v2.1/userinfo";
  const verifyIdTokenEndpoint = "https://api.line.me/oauth2/v2.1/verify";
  return {
    id: "line",
    name: "LINE",
    async createAuthorizationURL({
      state,
      scopes,
      codeVerifier,
      redirectURI,
      loginHint
    }) {
      const _scopes = options.disableDefaultScope ? [] : ["openid", "profile", "email"];
      options.scope && _scopes.push(...options.scope);
      scopes && _scopes.push(...scopes);
      return await createAuthorizationURL({
        id: "line",
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI,
        loginHint
      });
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, codeVerifier, redirectURI }) => {
      return validateAuthorizationCode({
        code,
        codeVerifier,
        redirectURI,
        options,
        tokenEndpoint
      });
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      return refreshAccessToken({
        refreshToken: refreshToken2,
        options: {
          clientId: options.clientId,
          clientSecret: options.clientSecret
        },
        tokenEndpoint
      });
    },
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      const body = new URLSearchParams();
      body.set("id_token", token);
      body.set("client_id", options.clientId);
      if (nonce) body.set("nonce", nonce);
      const { data, error: error3 } = await betterFetch(
        verifyIdTokenEndpoint,
        {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded"
          },
          body
        }
      );
      if (error3 || !data) {
        return false;
      }
      if (data.aud !== options.clientId) return false;
      if (nonce && data.nonce && data.nonce !== nonce) return false;
      return true;
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      let profile = null;
      if (token.idToken) {
        try {
          profile = decodeJwt(token.idToken);
        } catch {
        }
      }
      if (!profile) {
        const { data } = await betterFetch(userInfoEndpoint, {
          headers: {
            authorization: `Bearer ${token.accessToken}`
          }
        });
        profile = data || null;
      }
      if (!profile) return null;
      const userMap = await options.mapProfileToUser?.(profile);
      const id = profile.sub || profile.userId;
      const name = profile.name || profile.displayName;
      const image = profile.picture || profile.pictureUrl || void 0;
      const email3 = profile.email;
      return {
        user: {
          id,
          name,
          email: email3,
          image,
          // LINE does not expose email verification status in ID token/userinfo
          emailVerified: false,
          ...userMap
        },
        data: profile
      };
    },
    options
  };
}, "line");
var paypal = /* @__PURE__ */ __name((options) => {
  const environment = options.environment || "sandbox";
  const isSandbox = environment === "sandbox";
  const authorizationEndpoint = isSandbox ? "https://www.sandbox.paypal.com/signin/authorize" : "https://www.paypal.com/signin/authorize";
  const tokenEndpoint = isSandbox ? "https://api-m.sandbox.paypal.com/v1/oauth2/token" : "https://api-m.paypal.com/v1/oauth2/token";
  const userInfoEndpoint = isSandbox ? "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo" : "https://api-m.paypal.com/v1/identity/oauth2/userinfo";
  return {
    id: "paypal",
    name: "PayPal",
    async createAuthorizationURL({ state, codeVerifier, redirectURI }) {
      if (!options.clientId || !options.clientSecret) {
        logger.error(
          "Client Id and Client Secret is required for PayPal. Make sure to provide them in the options."
        );
        throw new BetterAuthError("CLIENT_ID_AND_SECRET_REQUIRED");
      }
      const _scopes = [];
      const url = await createAuthorizationURL({
        id: "paypal",
        options,
        authorizationEndpoint,
        scopes: _scopes,
        state,
        codeVerifier,
        redirectURI,
        prompt: options.prompt
      });
      return url;
    },
    validateAuthorizationCode: /* @__PURE__ */ __name(async ({ code, redirectURI }) => {
      const credentials = base642.encode(
        `${options.clientId}:${options.clientSecret}`
      );
      try {
        const response = await betterFetch(tokenEndpoint, {
          method: "POST",
          headers: {
            Authorization: `Basic ${credentials}`,
            Accept: "application/json",
            "Accept-Language": "en_US",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectURI
          }).toString()
        });
        if (!response.data) {
          throw new BetterAuthError("FAILED_TO_GET_ACCESS_TOKEN");
        }
        const data = response.data;
        const result = {
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          accessTokenExpiresAt: data.expires_in ? new Date(Date.now() + data.expires_in * 1e3) : void 0,
          idToken: data.id_token
        };
        return result;
      } catch (error3) {
        logger.error("PayPal token exchange failed:", error3);
        throw new BetterAuthError("FAILED_TO_GET_ACCESS_TOKEN");
      }
    }, "validateAuthorizationCode"),
    refreshAccessToken: options.refreshAccessToken ? options.refreshAccessToken : async (refreshToken2) => {
      const credentials = base642.encode(
        `${options.clientId}:${options.clientSecret}`
      );
      try {
        const response = await betterFetch(tokenEndpoint, {
          method: "POST",
          headers: {
            Authorization: `Basic ${credentials}`,
            Accept: "application/json",
            "Accept-Language": "en_US",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken2
          }).toString()
        });
        if (!response.data) {
          throw new BetterAuthError("FAILED_TO_REFRESH_ACCESS_TOKEN");
        }
        const data = response.data;
        return {
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          accessTokenExpiresAt: data.expires_in ? new Date(Date.now() + data.expires_in * 1e3) : void 0
        };
      } catch (error3) {
        logger.error("PayPal token refresh failed:", error3);
        throw new BetterAuthError("FAILED_TO_REFRESH_ACCESS_TOKEN");
      }
    },
    async verifyIdToken(token, nonce) {
      if (options.disableIdTokenSignIn) {
        return false;
      }
      if (options.verifyIdToken) {
        return options.verifyIdToken(token, nonce);
      }
      try {
        const payload = decodeJwt(token);
        return !!payload.sub;
      } catch (error3) {
        logger.error("Failed to verify PayPal ID token:", error3);
        return false;
      }
    },
    async getUserInfo(token) {
      if (options.getUserInfo) {
        return options.getUserInfo(token);
      }
      if (!token.accessToken) {
        logger.error("Access token is required to fetch PayPal user info");
        return null;
      }
      try {
        const response = await betterFetch(
          `${userInfoEndpoint}?schema=paypalv1.1`,
          {
            headers: {
              Authorization: `Bearer ${token.accessToken}`,
              Accept: "application/json"
            }
          }
        );
        if (!response.data) {
          logger.error("Failed to fetch user info from PayPal");
          return null;
        }
        const userInfo = response.data;
        const userMap = await options.mapProfileToUser?.(userInfo);
        const result = {
          user: {
            id: userInfo.user_id,
            name: userInfo.name,
            email: userInfo.email,
            image: userInfo.picture,
            emailVerified: userInfo.email_verified,
            ...userMap
          },
          data: userInfo
        };
        return result;
      } catch (error3) {
        logger.error("Failed to fetch user info from PayPal:", error3);
        return null;
      }
    },
    options
  };
}, "paypal");
var socialProviders = {
  apple,
  atlassian,
  cognito,
  discord,
  facebook,
  figma,
  github,
  microsoft,
  google,
  huggingface,
  slack,
  spotify,
  twitch,
  twitter,
  dropbox,
  kick,
  linear,
  linkedin,
  gitlab,
  tiktok,
  reddit,
  roblox,
  salesforce,
  vk,
  zoom,
  notion,
  kakao,
  naver,
  line,
  paypal
};
var socialProviderList = Object.keys(socialProviders);
var SocialProviderListEnum = _enum(socialProviderList).or(string2());
var signInSocial = createAuthEndpoint(
  "/sign-in/social",
  {
    method: "POST",
    body: object({
      /**
       * Callback URL to redirect to after the user
       * has signed in.
       */
      callbackURL: string2().meta({
        description: "Callback URL to redirect to after the user has signed in"
      }).optional(),
      /**
       * callback url to redirect if the user is newly registered.
       *
       * useful if you have different routes for existing users and new users
       */
      newUserCallbackURL: string2().optional(),
      /**
       * Callback url to redirect to if an error happens
       *
       * If it's initiated from the client sdk this defaults to
       * the current url.
       */
      errorCallbackURL: string2().meta({
        description: "Callback URL to redirect to if an error happens"
      }).optional(),
      /**
       * OAuth2 provider to use`
       */
      provider: SocialProviderListEnum,
      /**
       * Disable automatic redirection to the provider
       *
       * This is useful if you want to handle the redirection
       * yourself like in a popup or a different tab.
       */
      disableRedirect: boolean2().meta({
        description: "Disable automatic redirection to the provider. Useful for handling the redirection yourself"
      }).optional(),
      /**
       * ID token from the provider
       *
       * This is used to sign in the user
       * if the user is already signed in with the
       * provider in the frontend.
       *
       * Only applicable if the provider supports
       * it. Currently only `apple` and `google` is
       * supported out of the box.
       */
      idToken: optional(
        object({
          /**
           * ID token from the provider
           */
          token: string2().meta({
            description: "ID token from the provider"
          }),
          /**
           * The nonce used to generate the token
           */
          nonce: string2().meta({
            description: "Nonce used to generate the token"
          }).optional(),
          /**
           * Access token from the provider
           */
          accessToken: string2().meta({
            description: "Access token from the provider"
          }).optional(),
          /**
           * Refresh token from the provider
           */
          refreshToken: string2().meta({
            description: "Refresh token from the provider"
          }).optional(),
          /**
           * Expiry date of the token
           */
          expiresAt: number2().meta({
            description: "Expiry date of the token"
          }).optional()
        })
      ),
      scopes: array(string2()).meta({
        description: "Array of scopes to request from the provider. This will override the default scopes passed."
      }).optional(),
      /**
       * Explicitly request sign-up
       *
       * Should be used to allow sign up when
       * disableImplicitSignUp for this provider is
       * true
       */
      requestSignUp: boolean2().meta({
        description: "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider"
      }).optional(),
      /**
       * The login hint to use for the authorization code request
       */
      loginHint: string2().meta({
        description: "The login hint to use for the authorization code request"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Sign in with a social provider",
        operationId: "socialSignIn",
        responses: {
          "200": {
            description: "Success - Returns either session details or redirect URL",
            content: {
              "application/json": {
                schema: {
                  // todo: we need support for multiple schema
                  type: "object",
                  description: "Session response when idToken is provided",
                  properties: {
                    redirect: {
                      type: "boolean",
                      enum: [false]
                    },
                    token: {
                      type: "string",
                      description: "Session token",
                      url: {
                        type: "null",
                        nullable: true
                      },
                      user: {
                        type: "object",
                        properties: {
                          id: { type: "string" },
                          email: { type: "string" },
                          name: {
                            type: "string",
                            nullable: true
                          },
                          image: {
                            type: "string",
                            nullable: true
                          },
                          emailVerified: {
                            type: "boolean"
                          },
                          createdAt: {
                            type: "string",
                            format: "date-time"
                          },
                          updatedAt: {
                            type: "string",
                            format: "date-time"
                          }
                        },
                        required: [
                          "id",
                          "email",
                          "emailVerified",
                          "createdAt",
                          "updatedAt"
                        ]
                      }
                    }
                  },
                  required: ["redirect", "token", "user"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (c) => {
    const provider = c.context.socialProviders.find(
      (p) => p.id === c.body.provider
    );
    if (!provider) {
      c.context.logger.error(
        "Provider not found. Make sure to add the provider in your auth config",
        {
          provider: c.body.provider
        }
      );
      throw new APIError("NOT_FOUND", {
        message: BASE_ERROR_CODES.PROVIDER_NOT_FOUND
      });
    }
    if (c.body.idToken) {
      if (!provider.verifyIdToken) {
        c.context.logger.error(
          "Provider does not support id token verification",
          {
            provider: c.body.provider
          }
        );
        throw new APIError("NOT_FOUND", {
          message: BASE_ERROR_CODES.ID_TOKEN_NOT_SUPPORTED
        });
      }
      const { token, nonce } = c.body.idToken;
      const valid = await provider.verifyIdToken(token, nonce);
      if (!valid) {
        c.context.logger.error("Invalid id token", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.INVALID_TOKEN
        });
      }
      const userInfo = await provider.getUserInfo({
        idToken: token,
        accessToken: c.body.idToken.accessToken,
        refreshToken: c.body.idToken.refreshToken
      });
      if (!userInfo || !userInfo?.user) {
        c.context.logger.error("Failed to get user info", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.FAILED_TO_GET_USER_INFO
        });
      }
      if (!userInfo.user.email) {
        c.context.logger.error("User email not found", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.USER_EMAIL_NOT_FOUND
        });
      }
      const data = await handleOAuthUserInfo(c, {
        userInfo: {
          ...userInfo.user,
          email: userInfo.user.email,
          id: String(userInfo.user.id),
          name: userInfo.user.name || "",
          image: userInfo.user.image,
          emailVerified: userInfo.user.emailVerified || false
        },
        account: {
          providerId: provider.id,
          accountId: String(userInfo.user.id),
          accessToken: c.body.idToken.accessToken
        },
        callbackURL: c.body.callbackURL,
        disableSignUp: provider.disableImplicitSignUp && !c.body.requestSignUp || provider.disableSignUp
      });
      if (data.error) {
        throw new APIError("UNAUTHORIZED", {
          message: data.error
        });
      }
      await setSessionCookie(c, data.data);
      return c.json({
        redirect: false,
        token: data.data.session.token,
        url: void 0,
        user: {
          id: data.data.user.id,
          email: data.data.user.email,
          name: data.data.user.name,
          image: data.data.user.image,
          emailVerified: data.data.user.emailVerified,
          createdAt: data.data.user.createdAt,
          updatedAt: data.data.user.updatedAt
        }
      });
    }
    const { codeVerifier, state } = await generateState(c);
    const url = await provider.createAuthorizationURL({
      state,
      codeVerifier,
      redirectURI: `${c.context.baseURL}/callback/${provider.id}`,
      scopes: c.body.scopes,
      loginHint: c.body.loginHint
    });
    return c.json({
      url: url.toString(),
      redirect: !c.body.disableRedirect
    });
  }
);
var signInEmail = createAuthEndpoint(
  "/sign-in/email",
  {
    method: "POST",
    body: object({
      /**
       * Email of the user
       */
      email: string2().meta({
        description: "Email of the user"
      }),
      /**
       * Password of the user
       */
      password: string2().meta({
        description: "Password of the user"
      }),
      /**
       * Callback URL to use as a redirect for email
       * verification and for possible redirects
       */
      callbackURL: string2().meta({
        description: "Callback URL to use as a redirect for email verification"
      }).optional(),
      /**
       * If this is false, the session will not be remembered
       * @default true
       */
      rememberMe: boolean2().meta({
        description: "If this is false, the session will not be remembered. Default is `true`."
      }).default(true).optional()
    }),
    metadata: {
      openapi: {
        description: "Sign in with email and password",
        responses: {
          "200": {
            description: "Success - Returns either session details or redirect URL",
            content: {
              "application/json": {
                schema: {
                  // todo: we need support for multiple schema
                  type: "object",
                  description: "Session response when idToken is provided",
                  properties: {
                    redirect: {
                      type: "boolean",
                      enum: [false]
                    },
                    token: {
                      type: "string",
                      description: "Session token"
                    },
                    url: {
                      type: "null",
                      nullable: true
                    },
                    user: {
                      type: "object",
                      properties: {
                        id: { type: "string" },
                        email: { type: "string" },
                        name: {
                          type: "string",
                          nullable: true
                        },
                        image: {
                          type: "string",
                          nullable: true
                        },
                        emailVerified: {
                          type: "boolean"
                        },
                        createdAt: {
                          type: "string",
                          format: "date-time"
                        },
                        updatedAt: {
                          type: "string",
                          format: "date-time"
                        }
                      },
                      required: [
                        "id",
                        "email",
                        "emailVerified",
                        "createdAt",
                        "updatedAt"
                      ]
                    }
                  },
                  required: ["redirect", "token", "user"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options?.emailAndPassword?.enabled) {
      ctx.context.logger.error(
        "Email and password is not enabled. Make sure to enable it in the options on you `auth.ts` file. Check `https://better-auth.com/docs/authentication/email-password` for more!"
      );
      throw new APIError("BAD_REQUEST", {
        message: "Email and password is not enabled"
      });
    }
    const { email: email3, password } = ctx.body;
    const isValidEmail = string2().email().safeParse(email3);
    if (!isValidEmail.success) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.INVALID_EMAIL
      });
    }
    const user = await ctx.context.internalAdapter.findUserByEmail(email3, {
      includeAccounts: true
    });
    if (!user) {
      await ctx.context.password.hash(password);
      ctx.context.logger.error("User not found", { email: email3 });
      throw new APIError("UNAUTHORIZED", {
        message: BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD
      });
    }
    const credentialAccount = user.accounts.find(
      (a) => a.providerId === "credential"
    );
    if (!credentialAccount) {
      ctx.context.logger.error("Credential account not found", { email: email3 });
      throw new APIError("UNAUTHORIZED", {
        message: BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD
      });
    }
    const currentPassword = credentialAccount?.password;
    if (!currentPassword) {
      ctx.context.logger.error("Password not found", { email: email3 });
      throw new APIError("UNAUTHORIZED", {
        message: BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD
      });
    }
    const validPassword = await ctx.context.password.verify({
      hash: currentPassword,
      password
    });
    if (!validPassword) {
      ctx.context.logger.error("Invalid password");
      throw new APIError("UNAUTHORIZED", {
        message: BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD
      });
    }
    if (ctx.context.options?.emailAndPassword?.requireEmailVerification && !user.user.emailVerified) {
      if (!ctx.context.options?.emailVerification?.sendVerificationEmail) {
        throw new APIError("FORBIDDEN", {
          message: BASE_ERROR_CODES.EMAIL_NOT_VERIFIED
        });
      }
      if (ctx.context.options?.emailVerification?.sendOnSignIn) {
        const token = await createEmailVerificationToken(
          ctx.context.secret,
          user.user.email,
          void 0,
          ctx.context.options.emailVerification?.expiresIn
        );
        const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${ctx.body.callbackURL || "/"}`;
        await ctx.context.options.emailVerification.sendVerificationEmail(
          {
            user: user.user,
            url,
            token
          },
          ctx.request
        );
      }
      throw new APIError("FORBIDDEN", {
        message: BASE_ERROR_CODES.EMAIL_NOT_VERIFIED
      });
    }
    const session = await ctx.context.internalAdapter.createSession(
      user.user.id,
      ctx,
      ctx.body.rememberMe === false
    );
    if (!session) {
      ctx.context.logger.error("Failed to create session");
      throw new APIError("UNAUTHORIZED", {
        message: BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION
      });
    }
    await setSessionCookie(
      ctx,
      {
        session,
        user: user.user
      },
      ctx.body.rememberMe === false
    );
    return ctx.json({
      redirect: !!ctx.body.callbackURL,
      token: session.token,
      url: ctx.body.callbackURL,
      user: {
        id: user.user.id,
        email: user.user.email,
        name: user.user.name,
        image: user.user.image,
        emailVerified: user.user.emailVerified,
        createdAt: user.user.createdAt,
        updatedAt: user.user.updatedAt
      }
    });
  }
);
var schema = object({
  code: string2().optional(),
  error: string2().optional(),
  device_id: string2().optional(),
  error_description: string2().optional(),
  state: string2().optional(),
  user: string2().optional()
});
var callbackOAuth = createAuthEndpoint(
  "/callback/:id",
  {
    method: ["GET", "POST"],
    body: schema.optional(),
    query: schema.optional(),
    metadata: HIDE_METADATA
  },
  async (c) => {
    let queryOrBody;
    const defaultErrorURL = c.context.options.onAPIError?.errorURL || `${c.context.baseURL}/error`;
    try {
      if (c.method === "GET") {
        queryOrBody = schema.parse(c.query);
      } else if (c.method === "POST") {
        queryOrBody = schema.parse(c.body);
      } else {
        throw new Error("Unsupported method");
      }
    } catch (e) {
      c.context.logger.error("INVALID_CALLBACK_REQUEST", e);
      throw c.redirect(`${defaultErrorURL}?error=invalid_callback_request`);
    }
    const { code, error: error3, state, error_description, device_id } = queryOrBody;
    if (!state) {
      c.context.logger.error("State not found", error3);
      const sep = defaultErrorURL.includes("?") ? "&" : "?";
      const url = `${defaultErrorURL}${sep}state=state_not_found`;
      throw c.redirect(url);
    }
    const {
      codeVerifier,
      callbackURL,
      link,
      errorURL,
      newUserURL,
      requestSignUp
    } = await parseState(c);
    function redirectOnError(error22, description) {
      const baseURL = errorURL ?? defaultErrorURL;
      const params = new URLSearchParams({ error: error22 });
      if (description) params.set("error_description", description);
      const sep = baseURL.includes("?") ? "&" : "?";
      const url = `${baseURL}${sep}${params.toString()}`;
      throw c.redirect(url);
    }
    __name(redirectOnError, "redirectOnError");
    if (error3) {
      redirectOnError(error3, error_description);
    }
    if (!code) {
      c.context.logger.error("Code not found");
      throw redirectOnError("no_code");
    }
    const provider = c.context.socialProviders.find(
      (p) => p.id === c.params.id
    );
    if (!provider) {
      c.context.logger.error(
        "Oauth provider with id",
        c.params.id,
        "not found"
      );
      throw redirectOnError("oauth_provider_not_found");
    }
    let tokens;
    try {
      tokens = await provider.validateAuthorizationCode({
        code,
        codeVerifier,
        deviceId: device_id,
        redirectURI: `${c.context.baseURL}/callback/${provider.id}`
      });
    } catch (e) {
      c.context.logger.error("", e);
      throw redirectOnError("invalid_code");
    }
    const userInfo = await provider.getUserInfo({
      ...tokens,
      user: c.body?.user ? safeJSONParse(c.body.user) : void 0
    }).then((res) => res?.user);
    if (!userInfo) {
      c.context.logger.error("Unable to get user info");
      return redirectOnError("unable_to_get_user_info");
    }
    if (!callbackURL) {
      c.context.logger.error("No callback URL found");
      throw redirectOnError("no_callback_url");
    }
    if (link) {
      const trustedProviders = c.context.options.account?.accountLinking?.trustedProviders;
      const isTrustedProvider = trustedProviders?.includes(
        provider.id
      );
      if (!isTrustedProvider && !userInfo.emailVerified || c.context.options.account?.accountLinking?.enabled === false) {
        c.context.logger.error("Unable to link account - untrusted provider");
        return redirectOnError("unable_to_link_account");
      }
      if (userInfo.email !== link.email && c.context.options.account?.accountLinking?.allowDifferentEmails !== true) {
        return redirectOnError("email_doesn't_match");
      }
      const existingAccount = await c.context.internalAdapter.findAccount(
        String(userInfo.id)
      );
      if (existingAccount) {
        if (existingAccount.userId.toString() !== link.userId.toString()) {
          return redirectOnError("account_already_linked_to_different_user");
        }
        const updateData = Object.fromEntries(
          Object.entries({
            accessToken: await setTokenUtil(tokens.accessToken, c.context),
            refreshToken: await setTokenUtil(tokens.refreshToken, c.context),
            idToken: tokens.idToken,
            accessTokenExpiresAt: tokens.accessTokenExpiresAt,
            refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
            scope: tokens.scopes?.join(",")
          }).filter(([_, value]) => value !== void 0)
        );
        await c.context.internalAdapter.updateAccount(
          existingAccount.id,
          updateData
        );
      } else {
        const newAccount = await c.context.internalAdapter.createAccount(
          {
            userId: link.userId,
            providerId: provider.id,
            accountId: String(userInfo.id),
            ...tokens,
            accessToken: await setTokenUtil(tokens.accessToken, c.context),
            refreshToken: await setTokenUtil(tokens.refreshToken, c.context),
            scope: tokens.scopes?.join(",")
          },
          c
        );
        if (!newAccount) {
          return redirectOnError("unable_to_link_account");
        }
      }
      let toRedirectTo2;
      try {
        const url = callbackURL;
        toRedirectTo2 = url.toString();
      } catch {
        toRedirectTo2 = callbackURL;
      }
      throw c.redirect(toRedirectTo2);
    }
    if (!userInfo.email) {
      c.context.logger.error(
        "Provider did not return email. This could be due to misconfiguration in the provider settings."
      );
      return redirectOnError("email_not_found");
    }
    const result = await handleOAuthUserInfo(c, {
      userInfo: {
        ...userInfo,
        id: String(userInfo.id),
        email: userInfo.email,
        name: userInfo.name || userInfo.email
      },
      account: {
        providerId: provider.id,
        accountId: String(userInfo.id),
        ...tokens,
        scope: tokens.scopes?.join(",")
      },
      callbackURL,
      disableSignUp: provider.disableImplicitSignUp && !requestSignUp || provider.options?.disableSignUp,
      overrideUserInfo: provider.options?.overrideUserInfoOnSignIn
    });
    if (result.error) {
      c.context.logger.error(result.error.split(" ").join("_"));
      return redirectOnError(result.error.split(" ").join("_"));
    }
    const { session, user } = result.data;
    await setSessionCookie(c, {
      session,
      user
    });
    let toRedirectTo;
    try {
      const url = result.isRegister ? newUserURL || callbackURL : callbackURL;
      toRedirectTo = url.toString();
    } catch {
      toRedirectTo = result.isRegister ? newUserURL || callbackURL : callbackURL;
    }
    throw c.redirect(toRedirectTo);
  }
);
var signOut = createAuthEndpoint(
  "/sign-out",
  {
    method: "POST",
    requireHeaders: true,
    metadata: {
      openapi: {
        description: "Sign out the current user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: {
                      type: "boolean"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const sessionCookieToken = await ctx.getSignedCookie(
      ctx.context.authCookies.sessionToken.name,
      ctx.context.secret
    );
    if (!sessionCookieToken) {
      deleteSessionCookie(ctx);
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.FAILED_TO_GET_SESSION
      });
    }
    await ctx.context.internalAdapter.deleteSession(sessionCookieToken);
    deleteSessionCookie(ctx);
    return ctx.json({
      success: true
    });
  }
);
function redirectError(ctx, callbackURL, query) {
  const url = callbackURL ? new URL(callbackURL, ctx.baseURL) : new URL(`${ctx.baseURL}/error`);
  if (query)
    Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v));
  return url.href;
}
__name(redirectError, "redirectError");
function redirectCallback(ctx, callbackURL, query) {
  const url = new URL(callbackURL, ctx.baseURL);
  if (query)
    Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v));
  return url.href;
}
__name(redirectCallback, "redirectCallback");
var requestPasswordReset = createAuthEndpoint(
  "/request-password-reset",
  {
    method: "POST",
    body: object({
      /**
       * The email address of the user to send a password reset email to.
       */
      email: email2().meta({
        description: "The email address of the user to send a password reset email to"
      }),
      /**
       * The URL to redirect the user to reset their password.
       * If the token isn't valid or expired, it'll be redirected with a query parameter `?
       * error=INVALID_TOKEN`. If the token is valid, it'll be redirected with a query parameter `?
       * token=VALID_TOKEN
       */
      redirectTo: string2().meta({
        description: "The URL to redirect the user to reset their password. If the token isn't valid or expired, it'll be redirected with a query parameter `?error=INVALID_TOKEN`. If the token is valid, it'll be redirected with a query parameter `?token=VALID_TOKEN"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Send a password reset email to the user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean"
                    },
                    message: {
                      type: "string"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.emailAndPassword?.sendResetPassword) {
      ctx.context.logger.error(
        "Reset password isn't enabled.Please pass an emailAndPassword.sendResetPassword function in your auth config!"
      );
      throw new APIError("BAD_REQUEST", {
        message: "Reset password isn't enabled"
      });
    }
    const { email: email3, redirectTo } = ctx.body;
    const user = await ctx.context.internalAdapter.findUserByEmail(email3, {
      includeAccounts: true
    });
    if (!user) {
      ctx.context.logger.error("Reset Password: User not found", { email: email3 });
      return ctx.json({
        status: true,
        message: "If this email exists in our system, check your email for the reset link"
      });
    }
    const defaultExpiresIn = 60 * 60 * 1;
    const expiresAt = getDate(
      ctx.context.options.emailAndPassword.resetPasswordTokenExpiresIn || defaultExpiresIn,
      "sec"
    );
    const verificationToken = generateId(24);
    await ctx.context.internalAdapter.createVerificationValue(
      {
        value: user.user.id,
        identifier: `reset-password:${verificationToken}`,
        expiresAt
      },
      ctx
    );
    const callbackURL = redirectTo ? encodeURIComponent(redirectTo) : "";
    const url = `${ctx.context.baseURL}/reset-password/${verificationToken}?callbackURL=${callbackURL}`;
    await ctx.context.options.emailAndPassword.sendResetPassword(
      {
        user: user.user,
        url,
        token: verificationToken
      },
      ctx.request
    );
    return ctx.json({
      status: true,
      message: "If this email exists in our system, check your email for the reset link"
    });
  }
);
var forgetPassword = createAuthEndpoint(
  "/forget-password",
  {
    method: "POST",
    body: object({
      /**
       * The email address of the user to send a password reset email to.
       */
      email: string2().email().meta({
        description: "The email address of the user to send a password reset email to"
      }),
      /**
       * The URL to redirect the user to reset their password.
       * If the token isn't valid or expired, it'll be redirected with a query parameter `?
       * error=INVALID_TOKEN`. If the token is valid, it'll be redirected with a query parameter `?
       * token=VALID_TOKEN
       */
      redirectTo: string2().meta({
        description: "The URL to redirect the user to reset their password. If the token isn't valid or expired, it'll be redirected with a query parameter `?error=INVALID_TOKEN`. If the token is valid, it'll be redirected with a query parameter `?token=VALID_TOKEN"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Send a password reset email to the user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean"
                    },
                    message: {
                      type: "string"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.emailAndPassword?.sendResetPassword) {
      ctx.context.logger.error(
        "Reset password isn't enabled.Please pass an emailAndPassword.sendResetPassword function in your auth config!"
      );
      throw new APIError("BAD_REQUEST", {
        message: "Reset password isn't enabled"
      });
    }
    const { email: email3, redirectTo } = ctx.body;
    const user = await ctx.context.internalAdapter.findUserByEmail(email3, {
      includeAccounts: true
    });
    if (!user) {
      ctx.context.logger.error("Reset Password: User not found", { email: email3 });
      return ctx.json({
        status: true,
        message: "If this email exists in our system, check your email for the reset link"
      });
    }
    const defaultExpiresIn = 60 * 60 * 1;
    const expiresAt = getDate(
      ctx.context.options.emailAndPassword.resetPasswordTokenExpiresIn || defaultExpiresIn,
      "sec"
    );
    const verificationToken = generateId(24);
    await ctx.context.internalAdapter.createVerificationValue(
      {
        value: user.user.id,
        identifier: `reset-password:${verificationToken}`,
        expiresAt
      },
      ctx
    );
    const callbackURL = redirectTo ? encodeURIComponent(redirectTo) : "";
    const url = `${ctx.context.baseURL}/reset-password/${verificationToken}?callbackURL=${callbackURL}`;
    await ctx.context.options.emailAndPassword.sendResetPassword(
      {
        user: user.user,
        url,
        token: verificationToken
      },
      ctx.request
    );
    return ctx.json({
      status: true
    });
  }
);
var requestPasswordResetCallback = createAuthEndpoint(
  "/reset-password/:token",
  {
    method: "GET",
    query: object({
      callbackURL: string2().meta({
        description: "The URL to redirect the user to reset their password"
      })
    }),
    use: [originCheck((ctx) => ctx.query.callbackURL)],
    metadata: {
      openapi: {
        description: "Redirects the user to the callback URL with the token",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    token: {
                      type: "string"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const { token } = ctx.params;
    const { callbackURL } = ctx.query;
    if (!token || !callbackURL) {
      throw ctx.redirect(
        redirectError(ctx.context, callbackURL, { error: "INVALID_TOKEN" })
      );
    }
    const verification = await ctx.context.internalAdapter.findVerificationValue(
      `reset-password:${token}`
    );
    if (!verification || verification.expiresAt < /* @__PURE__ */ new Date()) {
      throw ctx.redirect(
        redirectError(ctx.context, callbackURL, { error: "INVALID_TOKEN" })
      );
    }
    throw ctx.redirect(redirectCallback(ctx.context, callbackURL, { token }));
  }
);
var resetPassword = createAuthEndpoint(
  "/reset-password",
  {
    method: "POST",
    query: object({
      token: string2().optional()
    }).optional(),
    body: object({
      newPassword: string2().meta({
        description: "The new password to set"
      }),
      token: string2().meta({
        description: "The token to reset the password"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Reset the password for a user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const token = ctx.body.token || ctx.query?.token;
    if (!token) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.INVALID_TOKEN
      });
    }
    const { newPassword } = ctx.body;
    const minLength = ctx.context.password?.config.minPasswordLength;
    const maxLength = ctx.context.password?.config.maxPasswordLength;
    if (newPassword.length < minLength) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_SHORT
      });
    }
    if (newPassword.length > maxLength) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_LONG
      });
    }
    const id = `reset-password:${token}`;
    const verification = await ctx.context.internalAdapter.findVerificationValue(id);
    if (!verification || verification.expiresAt < /* @__PURE__ */ new Date()) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.INVALID_TOKEN
      });
    }
    const userId = verification.value;
    const hashedPassword = await ctx.context.password.hash(newPassword);
    const accounts = await ctx.context.internalAdapter.findAccounts(userId);
    const account = accounts.find((ac) => ac.providerId === "credential");
    if (!account) {
      await ctx.context.internalAdapter.createAccount(
        {
          userId,
          providerId: "credential",
          password: hashedPassword,
          accountId: userId
        },
        ctx
      );
    } else {
      await ctx.context.internalAdapter.updatePassword(
        userId,
        hashedPassword,
        ctx
      );
    }
    await ctx.context.internalAdapter.deleteVerificationValue(verification.id);
    if (ctx.context.options.emailAndPassword?.onPasswordReset) {
      const user = await ctx.context.internalAdapter.findUserById(userId);
      if (user) {
        await ctx.context.options.emailAndPassword.onPasswordReset(
          {
            user
          },
          ctx.request
        );
      }
    }
    if (ctx.context.options.emailAndPassword?.revokeSessionsOnPasswordReset) {
      await ctx.context.internalAdapter.deleteSessions(userId);
    }
    return ctx.json({
      status: true
    });
  }
);
var changePassword = createAuthEndpoint(
  "/change-password",
  {
    method: "POST",
    body: object({
      /**
       * The new password to set
       */
      newPassword: string2().meta({
        description: "The new password to set"
      }),
      /**
       * The current password of the user
       */
      currentPassword: string2().meta({
        description: "The current password is required"
      }),
      /**
       * revoke all sessions that are not the
       * current one logged in by the user
       */
      revokeOtherSessions: boolean2().meta({
        description: "Must be a boolean value"
      }).optional()
    }),
    use: [sensitiveSessionMiddleware],
    metadata: {
      openapi: {
        description: "Change the password of the user",
        responses: {
          "200": {
            description: "Password successfully changed",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    token: {
                      type: "string",
                      nullable: true,
                      // Only present if revokeOtherSessions is true
                      description: "New session token if other sessions were revoked"
                    },
                    user: {
                      type: "object",
                      properties: {
                        id: {
                          type: "string",
                          description: "The unique identifier of the user"
                        },
                        email: {
                          type: "string",
                          format: "email",
                          description: "The email address of the user"
                        },
                        name: {
                          type: "string",
                          description: "The name of the user"
                        },
                        image: {
                          type: "string",
                          format: "uri",
                          nullable: true,
                          description: "The profile image URL of the user"
                        },
                        emailVerified: {
                          type: "boolean",
                          description: "Whether the email has been verified"
                        },
                        createdAt: {
                          type: "string",
                          format: "date-time",
                          description: "When the user was created"
                        },
                        updatedAt: {
                          type: "string",
                          format: "date-time",
                          description: "When the user was last updated"
                        }
                      },
                      required: [
                        "id",
                        "email",
                        "name",
                        "emailVerified",
                        "createdAt",
                        "updatedAt"
                      ]
                    }
                  },
                  required: ["user"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const { newPassword, currentPassword, revokeOtherSessions: revokeOtherSessions2 } = ctx.body;
    const session = ctx.context.session;
    const minPasswordLength = ctx.context.password.config.minPasswordLength;
    if (newPassword.length < minPasswordLength) {
      ctx.context.logger.error("Password is too short");
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_SHORT
      });
    }
    const maxPasswordLength = ctx.context.password.config.maxPasswordLength;
    if (newPassword.length > maxPasswordLength) {
      ctx.context.logger.error("Password is too long");
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_LONG
      });
    }
    const accounts = await ctx.context.internalAdapter.findAccounts(
      session.user.id
    );
    const account = accounts.find(
      (account2) => account2.providerId === "credential" && account2.password
    );
    if (!account || !account.password) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.CREDENTIAL_ACCOUNT_NOT_FOUND
      });
    }
    const passwordHash = await ctx.context.password.hash(newPassword);
    const verify = await ctx.context.password.verify({
      hash: account.password,
      password: currentPassword
    });
    if (!verify) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.INVALID_PASSWORD
      });
    }
    await ctx.context.internalAdapter.updateAccount(account.id, {
      password: passwordHash
    });
    let token = null;
    if (revokeOtherSessions2) {
      await ctx.context.internalAdapter.deleteSessions(session.user.id);
      const newSession = await ctx.context.internalAdapter.createSession(
        session.user.id,
        ctx
      );
      if (!newSession) {
        throw new APIError("INTERNAL_SERVER_ERROR", {
          message: BASE_ERROR_CODES.FAILED_TO_GET_SESSION
        });
      }
      await setSessionCookie(ctx, {
        session: newSession,
        user: session.user
      });
      token = newSession.token;
    }
    return ctx.json({
      token,
      user: {
        id: session.user.id,
        email: session.user.email,
        name: session.user.name,
        image: session.user.image,
        emailVerified: session.user.emailVerified,
        createdAt: session.user.createdAt,
        updatedAt: session.user.updatedAt
      }
    });
  }
);
var setPassword = createAuthEndpoint(
  "/set-password",
  {
    method: "POST",
    body: object({
      /**
       * The new password to set
       */
      newPassword: string2().meta({
        description: "The new password to set is required"
      })
    }),
    metadata: {
      SERVER_ONLY: true
    },
    use: [sensitiveSessionMiddleware]
  },
  async (ctx) => {
    const { newPassword } = ctx.body;
    const session = ctx.context.session;
    const minPasswordLength = ctx.context.password.config.minPasswordLength;
    if (newPassword.length < minPasswordLength) {
      ctx.context.logger.error("Password is too short");
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_SHORT
      });
    }
    const maxPasswordLength = ctx.context.password.config.maxPasswordLength;
    if (newPassword.length > maxPasswordLength) {
      ctx.context.logger.error("Password is too long");
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.PASSWORD_TOO_LONG
      });
    }
    const accounts = await ctx.context.internalAdapter.findAccounts(
      session.user.id
    );
    const account = accounts.find(
      (account2) => account2.providerId === "credential" && account2.password
    );
    const passwordHash = await ctx.context.password.hash(newPassword);
    if (!account) {
      await ctx.context.internalAdapter.linkAccount(
        {
          userId: session.user.id,
          providerId: "credential",
          accountId: session.user.id,
          password: passwordHash
        },
        ctx
      );
      return ctx.json({
        status: true
      });
    }
    throw new APIError("BAD_REQUEST", {
      message: "user already has a password"
    });
  }
);
var deleteUser = createAuthEndpoint(
  "/delete-user",
  {
    method: "POST",
    use: [sensitiveSessionMiddleware],
    body: object({
      /**
       * The callback URL to redirect to after the user is deleted
       * this is only used on delete user callback
       */
      callbackURL: string2().meta({
        description: "The callback URL to redirect to after the user is deleted"
      }).optional(),
      /**
       * The password of the user. If the password isn't provided, session freshness
       * will be checked.
       */
      password: string2().meta({
        description: "The password of the user is required to delete the user"
      }).optional(),
      /**
       * The token to delete the user. If the token is provided, the user will be deleted
       */
      token: string2().meta({
        description: "The token to delete the user is required"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Delete the user",
        responses: {
          "200": {
            description: "User deletion processed successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: {
                      type: "boolean",
                      description: "Indicates if the operation was successful"
                    },
                    message: {
                      type: "string",
                      enum: ["User deleted", "Verification email sent"],
                      description: "Status message of the deletion process"
                    }
                  },
                  required: ["success", "message"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.user?.deleteUser?.enabled) {
      ctx.context.logger.error(
        "Delete user is disabled. Enable it in the options",
        {
          session: ctx.context.session
        }
      );
      throw new APIError("NOT_FOUND");
    }
    const session = ctx.context.session;
    if (ctx.body.password) {
      const accounts = await ctx.context.internalAdapter.findAccounts(
        session.user.id
      );
      const account = accounts.find(
        (account2) => account2.providerId === "credential" && account2.password
      );
      if (!account || !account.password) {
        throw new APIError("BAD_REQUEST", {
          message: BASE_ERROR_CODES.CREDENTIAL_ACCOUNT_NOT_FOUND
        });
      }
      const verify = await ctx.context.password.verify({
        hash: account.password,
        password: ctx.body.password
      });
      if (!verify) {
        throw new APIError("BAD_REQUEST", {
          message: BASE_ERROR_CODES.INVALID_PASSWORD
        });
      }
    }
    if (ctx.body.token) {
      await deleteUserCallback({
        ...ctx,
        query: {
          token: ctx.body.token
        }
      });
      return ctx.json({
        success: true,
        message: "User deleted"
      });
    }
    if (ctx.context.options.user.deleteUser?.sendDeleteAccountVerification) {
      const token = generateRandomString(32, "0-9", "a-z");
      await ctx.context.internalAdapter.createVerificationValue(
        {
          value: session.user.id,
          identifier: `delete-account-${token}`,
          expiresAt: new Date(
            Date.now() + (ctx.context.options.user.deleteUser?.deleteTokenExpiresIn || 60 * 60 * 24) * 1e3
          )
        },
        ctx
      );
      const url = `${ctx.context.baseURL}/delete-user/callback?token=${token}&callbackURL=${ctx.body.callbackURL || "/"}`;
      await ctx.context.options.user.deleteUser.sendDeleteAccountVerification(
        {
          user: session.user,
          url,
          token
        },
        ctx.request
      );
      return ctx.json({
        success: true,
        message: "Verification email sent"
      });
    }
    if (!ctx.body.password && ctx.context.sessionConfig.freshAge !== 0) {
      const currentAge = new Date(session.session.createdAt).getTime();
      const freshAge = ctx.context.sessionConfig.freshAge * 1e3;
      const now = Date.now();
      if (now - currentAge > freshAge * 1e3) {
        throw new APIError("BAD_REQUEST", {
          message: BASE_ERROR_CODES.SESSION_EXPIRED
        });
      }
    }
    const beforeDelete = ctx.context.options.user.deleteUser?.beforeDelete;
    if (beforeDelete) {
      await beforeDelete(session.user, ctx.request);
    }
    await ctx.context.internalAdapter.deleteUser(session.user.id);
    await ctx.context.internalAdapter.deleteSessions(session.user.id);
    await ctx.context.internalAdapter.deleteAccounts(session.user.id);
    deleteSessionCookie(ctx);
    const afterDelete = ctx.context.options.user.deleteUser?.afterDelete;
    if (afterDelete) {
      await afterDelete(session.user, ctx.request);
    }
    return ctx.json({
      success: true,
      message: "User deleted"
    });
  }
);
var deleteUserCallback = createAuthEndpoint(
  "/delete-user/callback",
  {
    method: "GET",
    query: object({
      token: string2().meta({
        description: "The token to verify the deletion request"
      }),
      callbackURL: string2().meta({
        description: "The URL to redirect to after deletion"
      }).optional()
    }),
    use: [originCheck((ctx) => ctx.query.callbackURL)],
    metadata: {
      openapi: {
        description: "Callback to complete user deletion with verification token",
        responses: {
          "200": {
            description: "User successfully deleted",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: {
                      type: "boolean",
                      description: "Indicates if the deletion was successful"
                    },
                    message: {
                      type: "string",
                      enum: ["User deleted"],
                      description: "Confirmation message"
                    }
                  },
                  required: ["success", "message"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.user?.deleteUser?.enabled) {
      ctx.context.logger.error(
        "Delete user is disabled. Enable it in the options"
      );
      throw new APIError("NOT_FOUND");
    }
    const session = await getSessionFromCtx(ctx);
    if (!session) {
      throw new APIError("NOT_FOUND", {
        message: BASE_ERROR_CODES.FAILED_TO_GET_USER_INFO
      });
    }
    const token = await ctx.context.internalAdapter.findVerificationValue(
      `delete-account-${ctx.query.token}`
    );
    if (!token || token.expiresAt < /* @__PURE__ */ new Date()) {
      throw new APIError("NOT_FOUND", {
        message: BASE_ERROR_CODES.INVALID_TOKEN
      });
    }
    if (token.value !== session.user.id) {
      throw new APIError("NOT_FOUND", {
        message: BASE_ERROR_CODES.INVALID_TOKEN
      });
    }
    const beforeDelete = ctx.context.options.user.deleteUser?.beforeDelete;
    if (beforeDelete) {
      await beforeDelete(session.user, ctx.request);
    }
    await ctx.context.internalAdapter.deleteUser(session.user.id);
    await ctx.context.internalAdapter.deleteSessions(session.user.id);
    await ctx.context.internalAdapter.deleteAccounts(session.user.id);
    await ctx.context.internalAdapter.deleteVerificationValue(token.id);
    deleteSessionCookie(ctx);
    const afterDelete = ctx.context.options.user.deleteUser?.afterDelete;
    if (afterDelete) {
      await afterDelete(session.user, ctx.request);
    }
    if (ctx.query.callbackURL) {
      throw ctx.redirect(ctx.query.callbackURL || "/");
    }
    return ctx.json({
      success: true,
      message: "User deleted"
    });
  }
);
var changeEmail = createAuthEndpoint(
  "/change-email",
  {
    method: "POST",
    body: object({
      newEmail: email2().meta({
        description: "The new email address to set must be a valid email address"
      }),
      callbackURL: string2().meta({
        description: "The URL to redirect to after email verification"
      }).optional()
    }),
    use: [sensitiveSessionMiddleware],
    metadata: {
      openapi: {
        responses: {
          "200": {
            description: "Email change request processed successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean",
                      description: "Indicates if the request was successful"
                    },
                    message: {
                      type: "string",
                      enum: ["Email updated", "Verification email sent"],
                      description: "Status message of the email change process",
                      nullable: true
                    }
                  },
                  required: ["status"]
                }
              }
            }
          },
          "422": {
            description: "Unprocessable Entity. Email already exists",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    message: {
                      type: "string"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    if (!ctx.context.options.user?.changeEmail?.enabled) {
      ctx.context.logger.error("Change email is disabled.");
      throw new APIError("BAD_REQUEST", {
        message: "Change email is disabled"
      });
    }
    const newEmail = ctx.body.newEmail.toLowerCase();
    if (newEmail === ctx.context.session.user.email) {
      ctx.context.logger.error("Email is the same");
      throw new APIError("BAD_REQUEST", {
        message: "Email is the same"
      });
    }
    const existingUser = await ctx.context.internalAdapter.findUserByEmail(newEmail);
    if (existingUser) {
      ctx.context.logger.error("Email already exists");
      throw new APIError("BAD_REQUEST", {
        message: "Couldn't update your email"
      });
    }
    if (ctx.context.session.user.emailVerified !== true) {
      const existing = await ctx.context.internalAdapter.findUserByEmail(newEmail);
      if (existing) {
        throw new APIError("UNPROCESSABLE_ENTITY", {
          message: BASE_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL
        });
      }
      await ctx.context.internalAdapter.updateUserByEmail(
        ctx.context.session.user.email,
        {
          email: newEmail
        },
        ctx
      );
      await setSessionCookie(ctx, {
        session: ctx.context.session.session,
        user: {
          ...ctx.context.session.user,
          email: newEmail
        }
      });
      if (ctx.context.options.emailVerification?.sendVerificationEmail) {
        const token2 = await createEmailVerificationToken(
          ctx.context.secret,
          newEmail,
          void 0,
          ctx.context.options.emailVerification?.expiresIn
        );
        const url2 = `${ctx.context.baseURL}/verify-email?token=${token2}&callbackURL=${ctx.body.callbackURL || "/"}`;
        await ctx.context.options.emailVerification.sendVerificationEmail(
          {
            user: {
              ...ctx.context.session.user,
              email: newEmail
            },
            url: url2,
            token: token2
          },
          ctx.request
        );
      }
      return ctx.json({
        status: true
      });
    }
    if (!ctx.context.options.user.changeEmail.sendChangeEmailVerification) {
      ctx.context.logger.error("Verification email isn't enabled.");
      throw new APIError("BAD_REQUEST", {
        message: "Verification email isn't enabled"
      });
    }
    const token = await createEmailVerificationToken(
      ctx.context.secret,
      ctx.context.session.user.email,
      newEmail,
      ctx.context.options.emailVerification?.expiresIn
    );
    const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${ctx.body.callbackURL || "/"}`;
    await ctx.context.options.user.changeEmail.sendChangeEmailVerification(
      {
        user: ctx.context.session.user,
        newEmail,
        url,
        token
      },
      ctx.request
    );
    return ctx.json({
      status: true
    });
  }
);
function sanitize(input) {
  return input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
__name(sanitize, "sanitize");
var html = /* @__PURE__ */ __name((errorCode = "Unknown") => `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        :root {
            --bg-color: #f8f9fa;
            --text-color: #212529;
            --accent-color: #000000;
            --error-color: #dc3545;
            --border-color: #e9ecef;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            line-height: 1.5;
        }
        .error-container {
            background-color: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            padding: 2.5rem;
            text-align: center;
            max-width: 90%;
            width: 400px;
        }
        h1 {
            color: var(--error-color);
            font-size: 1.75rem;
            margin-bottom: 1rem;
            font-weight: 600;
        }
        p {
            margin-bottom: 1.5rem;
            color: #495057;
        }
        .btn {
            background-color: var(--accent-color);
            color: #ffffff;
            text-decoration: none;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            transition: all 0.3s ease;
            display: inline-block;
            font-weight: 500;
            border: 2px solid var(--accent-color);
        }
        .btn:hover {
            background-color: #131721;
        }
        .error-code {
            font-size: 0.875rem;
            color: #6c757d;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }
        .icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="icon">\u26A0\uFE0F</div>
        <h1>Better Auth Error</h1>
        <p>We encountered an issue while processing your request. Please try again or contact the application owner if the problem persists.</p>
        <a href="/" id="returnLink" class="btn">Return to Application</a>
        <div class="error-code">Error Code: <span id="errorCode">${sanitize(
  errorCode
)}</span></div>
    </div>
</body>
</html>`, "html");
var error2 = createAuthEndpoint(
  "/error",
  {
    method: "GET",
    metadata: {
      ...HIDE_METADATA,
      openapi: {
        description: "Displays an error page",
        responses: {
          "200": {
            description: "Success",
            content: {
              "text/html": {
                schema: {
                  type: "string",
                  description: "The HTML content of the error page"
                }
              }
            }
          }
        }
      }
    }
  },
  async (c) => {
    const query = new URL(c.request?.url || "").searchParams.get("error") || "Unknown";
    return new Response(html(query), {
      headers: {
        "Content-Type": "text/html"
      }
    });
  }
);
var ok = createAuthEndpoint(
  "/ok",
  {
    method: "GET",
    metadata: {
      ...HIDE_METADATA,
      openapi: {
        description: "Check if the API is working",
        responses: {
          "200": {
            description: "API is working",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: {
                      type: "boolean",
                      description: "Indicates if the API is working"
                    }
                  },
                  required: ["ok"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    return ctx.json({
      ok: true
    });
  }
);
var listUserAccounts = createAuthEndpoint(
  "/list-accounts",
  {
    method: "GET",
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        description: "List all accounts linked to the user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      id: {
                        type: "string"
                      },
                      providerId: {
                        type: "string"
                      },
                      createdAt: {
                        type: "string",
                        format: "date-time"
                      },
                      updatedAt: {
                        type: "string",
                        format: "date-time"
                      },
                      accountId: {
                        type: "string"
                      },
                      scopes: {
                        type: "array",
                        items: {
                          type: "string"
                        }
                      }
                    },
                    required: [
                      "id",
                      "providerId",
                      "createdAt",
                      "updatedAt",
                      "accountId",
                      "scopes"
                    ]
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (c) => {
    const session = c.context.session;
    const accounts = await c.context.internalAdapter.findAccounts(
      session.user.id
    );
    return c.json(
      accounts.map((a) => ({
        id: a.id,
        providerId: a.providerId,
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
        accountId: a.accountId,
        scopes: a.scope?.split(",") || []
      }))
    );
  }
);
var linkSocialAccount = createAuthEndpoint(
  "/link-social",
  {
    method: "POST",
    requireHeaders: true,
    body: object({
      /**
       * Callback URL to redirect to after the user has signed in.
       */
      callbackURL: string2().meta({
        description: "The URL to redirect to after the user has signed in"
      }).optional(),
      /**
       * OAuth2 provider to use
       */
      provider: SocialProviderListEnum,
      /**
       * ID Token for direct authentication without redirect
       */
      idToken: object({
        token: string2(),
        nonce: string2().optional(),
        accessToken: string2().optional(),
        refreshToken: string2().optional(),
        scopes: array(string2()).optional()
      }).optional(),
      /**
       * Whether to allow sign up for new users
       */
      requestSignUp: boolean2().optional(),
      /**
       * Additional scopes to request when linking the account.
       * This is useful for requesting additional permissions when
       * linking a social account compared to the initial authentication.
       */
      scopes: array(string2()).meta({
        description: "Additional scopes to request from the provider"
      }).optional(),
      /**
       * The URL to redirect to if there is an error during the link process.
       */
      errorCallbackURL: string2().meta({
        description: "The URL to redirect to if there is an error during the link process"
      }).optional(),
      /**
       * Disable automatic redirection to the provider
       *
       * This is useful if you want to handle the redirection
       * yourself like in a popup or a different tab.
       */
      disableRedirect: boolean2().meta({
        description: "Disable automatic redirection to the provider. Useful for handling the redirection yourself"
      }).optional()
    }),
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        description: "Link a social account to the user",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    url: {
                      type: "string",
                      description: "The authorization URL to redirect the user to"
                    },
                    redirect: {
                      type: "boolean",
                      description: "Indicates if the user should be redirected to the authorization URL"
                    },
                    status: {
                      type: "boolean"
                    }
                  },
                  required: ["redirect"]
                }
              }
            }
          }
        }
      }
    }
  },
  async (c) => {
    const session = c.context.session;
    const provider = c.context.socialProviders.find(
      (p) => p.id === c.body.provider
    );
    if (!provider) {
      c.context.logger.error(
        "Provider not found. Make sure to add the provider in your auth config",
        {
          provider: c.body.provider
        }
      );
      throw new APIError("NOT_FOUND", {
        message: BASE_ERROR_CODES.PROVIDER_NOT_FOUND
      });
    }
    if (c.body.idToken) {
      if (!provider.verifyIdToken) {
        c.context.logger.error(
          "Provider does not support id token verification",
          {
            provider: c.body.provider
          }
        );
        throw new APIError("NOT_FOUND", {
          message: BASE_ERROR_CODES.ID_TOKEN_NOT_SUPPORTED
        });
      }
      const { token, nonce } = c.body.idToken;
      const valid = await provider.verifyIdToken(token, nonce);
      if (!valid) {
        c.context.logger.error("Invalid id token", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.INVALID_TOKEN
        });
      }
      const linkingUserInfo = await provider.getUserInfo({
        idToken: token,
        accessToken: c.body.idToken.accessToken,
        refreshToken: c.body.idToken.refreshToken
      });
      if (!linkingUserInfo || !linkingUserInfo?.user) {
        c.context.logger.error("Failed to get user info", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.FAILED_TO_GET_USER_INFO
        });
      }
      const linkingUserId = String(linkingUserInfo.user.id);
      if (!linkingUserInfo.user.email) {
        c.context.logger.error("User email not found", {
          provider: c.body.provider
        });
        throw new APIError("UNAUTHORIZED", {
          message: BASE_ERROR_CODES.USER_EMAIL_NOT_FOUND
        });
      }
      const existingAccounts = await c.context.internalAdapter.findAccounts(
        session.user.id
      );
      const hasBeenLinked = existingAccounts.find(
        (a) => a.providerId === provider.id && a.accountId === linkingUserId
      );
      if (hasBeenLinked) {
        return c.json({
          url: "",
          // this is for type inference
          status: true,
          redirect: false
        });
      }
      const trustedProviders = c.context.options.account?.accountLinking?.trustedProviders;
      const isTrustedProvider = trustedProviders?.includes(provider.id);
      if (!isTrustedProvider && !linkingUserInfo.user.emailVerified || c.context.options.account?.accountLinking?.enabled === false) {
        throw new APIError("UNAUTHORIZED", {
          message: "Account not linked - linking not allowed"
        });
      }
      if (linkingUserInfo.user.email !== session.user.email && c.context.options.account?.accountLinking?.allowDifferentEmails !== true) {
        throw new APIError("UNAUTHORIZED", {
          message: "Account not linked - different emails not allowed"
        });
      }
      try {
        await c.context.internalAdapter.createAccount(
          {
            userId: session.user.id,
            providerId: provider.id,
            accountId: linkingUserId,
            accessToken: c.body.idToken.accessToken,
            idToken: token,
            refreshToken: c.body.idToken.refreshToken,
            scope: c.body.idToken.scopes?.join(",")
          },
          c
        );
      } catch (e) {
        throw new APIError("EXPECTATION_FAILED", {
          message: "Account not linked - unable to create account"
        });
      }
      if (c.context.options.account?.accountLinking?.updateUserInfoOnLink === true) {
        try {
          await c.context.internalAdapter.updateUser(session.user.id, {
            name: linkingUserInfo.user?.name,
            image: linkingUserInfo.user?.image
          });
        } catch (e) {
          console.warn("Could not update user - " + e.toString());
        }
      }
      return c.json({
        url: "",
        // this is for type inference
        status: true,
        redirect: false
      });
    }
    const state = await generateState(c, {
      userId: session.user.id,
      email: session.user.email
    });
    const url = await provider.createAuthorizationURL({
      state: state.state,
      codeVerifier: state.codeVerifier,
      redirectURI: `${c.context.baseURL}/callback/${provider.id}`,
      scopes: c.body.scopes
    });
    return c.json({
      url: url.toString(),
      redirect: !c.body.disableRedirect
    });
  }
);
var unlinkAccount = createAuthEndpoint(
  "/unlink-account",
  {
    method: "POST",
    body: object({
      providerId: string2(),
      accountId: string2().optional()
    }),
    use: [freshSessionMiddleware],
    metadata: {
      openapi: {
        description: "Unlink an account",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "boolean"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  async (ctx) => {
    const { providerId, accountId } = ctx.body;
    const accounts = await ctx.context.internalAdapter.findAccounts(
      ctx.context.session.user.id
    );
    if (accounts.length === 1 && !ctx.context.options.account?.accountLinking?.allowUnlinkingAll) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.FAILED_TO_UNLINK_LAST_ACCOUNT
      });
    }
    const accountExist = accounts.find(
      (account) => accountId ? account.accountId === accountId && account.providerId === providerId : account.providerId === providerId
    );
    if (!accountExist) {
      throw new APIError("BAD_REQUEST", {
        message: BASE_ERROR_CODES.ACCOUNT_NOT_FOUND
      });
    }
    await ctx.context.internalAdapter.deleteAccount(accountExist.id);
    return ctx.json({
      status: true
    });
  }
);
var getAccessToken = createAuthEndpoint(
  "/get-access-token",
  {
    method: "POST",
    body: object({
      providerId: string2().meta({
        description: "The provider ID for the OAuth provider"
      }),
      accountId: string2().meta({
        description: "The account ID associated with the refresh token"
      }).optional(),
      userId: string2().meta({
        description: "The user ID associated with the account"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Get a valid access token, doing a refresh if needed",
        responses: {
          200: {
            description: "A Valid access token",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    tokenType: {
                      type: "string"
                    },
                    idToken: {
                      type: "string"
                    },
                    accessToken: {
                      type: "string"
                    },
                    refreshToken: {
                      type: "string"
                    },
                    accessTokenExpiresAt: {
                      type: "string",
                      format: "date-time"
                    },
                    refreshTokenExpiresAt: {
                      type: "string",
                      format: "date-time"
                    }
                  }
                }
              }
            }
          },
          400: {
            description: "Invalid refresh token or provider configuration"
          }
        }
      }
    }
  },
  async (ctx) => {
    const { providerId, accountId, userId } = ctx.body;
    const req = ctx.request;
    const session = await getSessionFromCtx(ctx);
    if (req && !session) {
      throw ctx.error("UNAUTHORIZED");
    }
    let resolvedUserId = session?.user?.id || userId;
    if (!resolvedUserId) {
      throw new APIError("BAD_REQUEST", {
        message: `Either userId or session is required`
      });
    }
    if (!ctx.context.socialProviders.find((p) => p.id === providerId)) {
      throw new APIError("BAD_REQUEST", {
        message: `Provider ${providerId} is not supported.`
      });
    }
    const accounts = await ctx.context.internalAdapter.findAccounts(resolvedUserId);
    const account = accounts.find(
      (acc) => accountId ? acc.id === accountId && acc.providerId === providerId : acc.providerId === providerId
    );
    if (!account) {
      throw new APIError("BAD_REQUEST", {
        message: "Account not found"
      });
    }
    const provider = ctx.context.socialProviders.find(
      (p) => p.id === providerId
    );
    if (!provider) {
      throw new APIError("BAD_REQUEST", {
        message: `Provider ${providerId} not found.`
      });
    }
    try {
      let newTokens = null;
      const accessTokenExpired = account.accessTokenExpiresAt && new Date(account.accessTokenExpiresAt).getTime() - Date.now() < 5e3;
      if (account.refreshToken && accessTokenExpired && provider.refreshAccessToken) {
        newTokens = await provider.refreshAccessToken(
          account.refreshToken
        );
        await ctx.context.internalAdapter.updateAccount(account.id, {
          accessToken: await setTokenUtil(newTokens.accessToken, ctx.context),
          accessTokenExpiresAt: newTokens.accessTokenExpiresAt,
          refreshToken: await setTokenUtil(newTokens.refreshToken, ctx.context),
          refreshTokenExpiresAt: newTokens.refreshTokenExpiresAt
        });
      }
      const tokens = {
        accessToken: await decryptOAuthToken(
          newTokens?.accessToken ?? account.accessToken ?? "",
          ctx.context
        ),
        accessTokenExpiresAt: newTokens?.accessTokenExpiresAt ?? account.accessTokenExpiresAt ?? void 0,
        scopes: account.scope?.split(",") ?? [],
        idToken: newTokens?.idToken ?? account.idToken ?? void 0
      };
      return ctx.json(tokens);
    } catch (error3) {
      throw new APIError("BAD_REQUEST", {
        message: "Failed to get a valid access token",
        cause: error3
      });
    }
  }
);
var refreshToken = createAuthEndpoint(
  "/refresh-token",
  {
    method: "POST",
    body: object({
      providerId: string2().meta({
        description: "The provider ID for the OAuth provider"
      }),
      accountId: string2().meta({
        description: "The account ID associated with the refresh token"
      }).optional(),
      userId: string2().meta({
        description: "The user ID associated with the account"
      }).optional()
    }),
    metadata: {
      openapi: {
        description: "Refresh the access token using a refresh token",
        responses: {
          200: {
            description: "Access token refreshed successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    tokenType: {
                      type: "string"
                    },
                    idToken: {
                      type: "string"
                    },
                    accessToken: {
                      type: "string"
                    },
                    refreshToken: {
                      type: "string"
                    },
                    accessTokenExpiresAt: {
                      type: "string",
                      format: "date-time"
                    },
                    refreshTokenExpiresAt: {
                      type: "string",
                      format: "date-time"
                    }
                  }
                }
              }
            }
          },
          400: {
            description: "Invalid refresh token or provider configuration"
          }
        }
      }
    }
  },
  async (ctx) => {
    const { providerId, accountId, userId } = ctx.body;
    const req = ctx.request;
    const session = await getSessionFromCtx(ctx);
    if (req && !session) {
      throw ctx.error("UNAUTHORIZED");
    }
    let resolvedUserId = session?.user?.id || userId;
    if (!resolvedUserId) {
      throw new APIError("BAD_REQUEST", {
        message: `Either userId or session is required`
      });
    }
    const accounts = await ctx.context.internalAdapter.findAccounts(resolvedUserId);
    const account = accounts.find(
      (acc) => accountId ? acc.id === accountId && acc.providerId === providerId : acc.providerId === providerId
    );
    if (!account) {
      throw new APIError("BAD_REQUEST", {
        message: "Account not found"
      });
    }
    const provider = ctx.context.socialProviders.find(
      (p) => p.id === providerId
    );
    if (!provider) {
      throw new APIError("BAD_REQUEST", {
        message: `Provider ${providerId} not found.`
      });
    }
    if (!provider.refreshAccessToken) {
      throw new APIError("BAD_REQUEST", {
        message: `Provider ${providerId} does not support token refreshing.`
      });
    }
    try {
      const tokens = await provider.refreshAccessToken(
        account.refreshToken
      );
      await ctx.context.internalAdapter.updateAccount(account.id, {
        accessToken: await setTokenUtil(tokens.accessToken, ctx.context),
        refreshToken: await setTokenUtil(tokens.refreshToken, ctx.context),
        accessTokenExpiresAt: tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: tokens.refreshTokenExpiresAt
      });
      return ctx.json(tokens);
    } catch (error3) {
      throw new APIError("BAD_REQUEST", {
        message: "Failed to refresh access token",
        cause: error3
      });
    }
  }
);
var accountInfo = createAuthEndpoint(
  "/account-info",
  {
    method: "POST",
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        description: "Get the account info provided by the provider",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    user: {
                      type: "object",
                      properties: {
                        id: {
                          type: "string"
                        },
                        name: {
                          type: "string"
                        },
                        email: {
                          type: "string"
                        },
                        image: {
                          type: "string"
                        },
                        emailVerified: {
                          type: "boolean"
                        }
                      },
                      required: ["id", "emailVerified"]
                    },
                    data: {
                      type: "object",
                      properties: {},
                      additionalProperties: true
                    }
                  },
                  required: ["user", "data"],
                  additionalProperties: false
                }
              }
            }
          }
        }
      }
    },
    body: object({
      accountId: string2().meta({
        description: "The provider given account id for which to get the account info"
      })
    })
  },
  async (ctx) => {
    const account = await ctx.context.internalAdapter.findAccount(
      ctx.body.accountId
    );
    if (!account || account.userId !== ctx.context.session.user.id) {
      throw new APIError("BAD_REQUEST", {
        message: "Account not found"
      });
    }
    const provider = ctx.context.socialProviders.find(
      (p) => p.id === account.providerId
    );
    if (!provider) {
      throw new APIError("INTERNAL_SERVER_ERROR", {
        message: `Provider account provider is ${account.providerId} but it is not configured`
      });
    }
    const tokens = await getAccessToken({
      ...ctx,
      body: {
        accountId: account.id,
        providerId: account.providerId
      },
      returnHeaders: false
    });
    if (!tokens.accessToken) {
      throw new APIError("BAD_REQUEST", {
        message: "Access token not found"
      });
    }
    const info = await provider.getUserInfo({
      ...tokens,
      accessToken: tokens.accessToken
    });
    return ctx.json(info);
  }
);
var defuReplaceArrays = createDefu((obj, key, value) => {
  if (Array.isArray(obj[key]) && Array.isArray(value)) {
    obj[key] = value;
    return true;
  }
});

// node_modules/better-auth/dist/shared/better-auth.msGOU0m9.mjs
var SPECIAL_VALUES = {
  true: true,
  false: false,
  null: null,
  undefined: void 0,
  nan: Number.NaN,
  infinity: Number.POSITIVE_INFINITY,
  "-infinity": Number.NEGATIVE_INFINITY
};

// node_modules/better-auth/dist/shared/better-auth.CJoIWSTC.mjs
var orgMiddleware = createAuthMiddleware(async () => {
  return {};
});
var orgSessionMiddleware = createAuthMiddleware(
  {
    use: [sessionMiddleware]
  },
  async (ctx) => {
    const session = ctx.context.session;
    return {
      session
    };
  }
);
var role = string2();
var invitationStatus = _enum(["pending", "accepted", "rejected", "canceled"]).default("pending");
object({
  id: string2().default(generateId),
  name: string2(),
  slug: string2(),
  logo: string2().nullish().optional(),
  metadata: record(string2(), unknown()).or(string2().transform((v) => JSON.parse(v))).optional(),
  createdAt: date3()
});
object({
  id: string2().default(generateId),
  organizationId: string2(),
  userId: coerce_exports.string(),
  role,
  createdAt: date3().default(() => /* @__PURE__ */ new Date())
});
object({
  id: string2().default(generateId),
  organizationId: string2(),
  email: string2(),
  role,
  status: invitationStatus,
  teamId: string2().nullish(),
  inviterId: string2(),
  expiresAt: date3()
});
var teamSchema = object({
  id: string2().default(generateId),
  name: string2().min(1),
  organizationId: string2(),
  createdAt: date3(),
  updatedAt: date3().optional()
});
object({
  id: string2().default(generateId),
  teamId: string2(),
  userId: string2(),
  createdAt: date3().default(() => /* @__PURE__ */ new Date())
});
object({
  id: string2().default(generateId),
  organizationId: string2(),
  role: string2(),
  permission: record(string2(), array(string2())),
  createdAt: date3().default(() => /* @__PURE__ */ new Date()),
  updatedAt: date3().optional()
});
var defaultRoles = ["admin", "member", "owner"];
union([
  _enum(defaultRoles),
  array(_enum(defaultRoles))
]);

// node_modules/better-auth/dist/plugins/access/index.mjs
function role2(statements) {
  return {
    authorize(request, connector = "AND") {
      let success = false;
      for (const [requestedResource, requestedActions] of Object.entries(
        request
      )) {
        const allowedActions = statements[requestedResource];
        if (!allowedActions) {
          return {
            success: false,
            error: `You are not allowed to access resource: ${requestedResource}`
          };
        }
        if (Array.isArray(requestedActions)) {
          success = requestedActions.every(
            (requestedAction) => allowedActions.includes(requestedAction)
          );
        } else {
          if (typeof requestedActions === "object") {
            const actions = requestedActions;
            if (actions.connector === "OR") {
              success = actions.actions.some(
                (requestedAction) => allowedActions.includes(requestedAction)
              );
            } else {
              success = actions.actions.every(
                (requestedAction) => allowedActions.includes(requestedAction)
              );
            }
          } else {
            throw new BetterAuthError("Invalid access control request");
          }
        }
        if (success && connector === "OR") {
          return { success };
        }
        if (!success && connector === "AND") {
          return {
            success: false,
            error: `unauthorized to access resource "${requestedResource}"`
          };
        }
      }
      if (success) {
        return {
          success
        };
      }
      return {
        success: false,
        error: "Not authorized"
      };
    },
    statements
  };
}
__name(role2, "role");
function createAccessControl(s2) {
  return {
    newRole(statements) {
      return role2(statements);
    },
    statements: s2
  };
}
__name(createAccessControl, "createAccessControl");

// node_modules/better-auth/dist/plugins/organization/access/index.mjs
var defaultStatements = {
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"]
};
var defaultAc = createAccessControl(defaultStatements);
var adminAc = defaultAc.newRole({
  organization: ["update"],
  invitation: ["create", "cancel"],
  member: ["create", "update", "delete"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"]
});
var ownerAc = defaultAc.newRole({
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"]
});
var memberAc = defaultAc.newRole({
  organization: [],
  member: [],
  invitation: [],
  team: [],
  ac: ["read"]
  // Allow members to see all roles for their org.
});

// node_modules/better-auth/dist/shared/better-auth.wna9p9JG.mjs
var ORGANIZATION_ERROR_CODES = defineErrorCodes({
  YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION: "You are not allowed to create a new organization",
  YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS: "You have reached the maximum number of organizations",
  ORGANIZATION_ALREADY_EXISTS: "Organization already exists",
  ORGANIZATION_NOT_FOUND: "Organization not found",
  USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION: "User is not a member of the organization",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION: "You are not allowed to update this organization",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION: "You are not allowed to delete this organization",
  NO_ACTIVE_ORGANIZATION: "No active organization",
  USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION: "User is already a member of this organization",
  MEMBER_NOT_FOUND: "Member not found",
  ROLE_NOT_FOUND: "Role not found",
  YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM: "You are not allowed to create a new team",
  TEAM_ALREADY_EXISTS: "Team already exists",
  TEAM_NOT_FOUND: "Team not found",
  YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER: "You cannot leave the organization as the only owner",
  YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER: "You cannot leave the organization without an owner",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER: "You are not allowed to delete this member",
  YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION: "You are not allowed to invite users to this organization",
  USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION: "User is already invited to this organization",
  INVITATION_NOT_FOUND: "Invitation not found",
  YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION: "You are not the recipient of the invitation",
  EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION: "Email verification required before accepting or rejecting invitation",
  YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION: "You are not allowed to cancel this invitation",
  INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION: "Inviter is no longer a member of the organization",
  YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE: "You are not allowed to invite a user with this role",
  FAILED_TO_RETRIEVE_INVITATION: "Failed to retrieve invitation",
  YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS: "You have reached the maximum number of teams",
  UNABLE_TO_REMOVE_LAST_TEAM: "Unable to remove last team",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER: "You are not allowed to update this member",
  ORGANIZATION_MEMBERSHIP_LIMIT_REACHED: "Organization membership limit reached",
  YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION: "You are not allowed to create teams in this organization",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION: "You are not allowed to delete teams in this organization",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM: "You are not allowed to update this team",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM: "You are not allowed to delete this team",
  INVITATION_LIMIT_REACHED: "Invitation limit reached",
  TEAM_MEMBER_LIMIT_REACHED: "Team member limit reached",
  USER_IS_NOT_A_MEMBER_OF_THE_TEAM: "User is not a member of the team",
  YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM: "You are not allowed to list the members of this team",
  YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM: "You do not have an active team",
  YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER: "You are not allowed to create a new member",
  YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER: "You are not allowed to remove a team member",
  YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION: "You are not allowed to access this organization as an owner",
  YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION: "You are not a member of this organization",
  MISSING_AC_INSTANCE: "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
  YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE: "You must be in an organization to create a role",
  YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE: "You are not allowed to create a role",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE: "You are not allowed to update a role",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE: "You are not allowed to delete a role",
  YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE: "You are not allowed to read a role",
  YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE: "You are not allowed to list a role",
  YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE: "You are not allowed to get a role",
  TOO_MANY_ROLES: "This organization has too many roles",
  INVALID_RESOURCE: "The provided permission includes an invalid resource",
  ROLE_NAME_IS_ALREADY_TAKEN: "That role name is already taken",
  CANNOT_DELETE_A_PRE_DEFINED_ROLE: "Cannot delete a pre-defined role"
});
var DEFAULT_MAXIMUM_ROLES_PER_ORGANIZATION = Number.POSITIVE_INFINITY;

// node_modules/better-auth/dist/plugins/username/index.mjs
var USERNAME_ERROR_CODES = defineErrorCodes({
  INVALID_USERNAME_OR_PASSWORD: "Invalid username or password",
  EMAIL_NOT_VERIFIED: "Email not verified",
  UNEXPECTED_ERROR: "Unexpected error",
  USERNAME_IS_ALREADY_TAKEN: "Username is already taken. Please try another.",
  USERNAME_TOO_SHORT: "Username is too short",
  USERNAME_TOO_LONG: "Username is too long",
  INVALID_USERNAME: "Username is invalid",
  INVALID_DISPLAY_USERNAME: "Display username is invalid"
});

// node_modules/better-auth/dist/plugins/admin/access/index.mjs
var defaultStatements2 = {
  user: [
    "create",
    "list",
    "set-role",
    "ban",
    "impersonate",
    "delete",
    "set-password",
    "get",
    "update"
  ],
  session: ["list", "revoke", "delete"]
};
var defaultAc2 = createAccessControl(defaultStatements2);
var adminAc2 = defaultAc2.newRole({
  user: [
    "create",
    "list",
    "set-role",
    "ban",
    "impersonate",
    "delete",
    "set-password",
    "get",
    "update"
  ],
  session: ["list", "revoke", "delete"]
});
var userAc = defaultAc2.newRole({
  user: [],
  session: []
});

// node_modules/better-auth/dist/shared/better-auth.B4NXoE-M.mjs
var ADMIN_ERROR_CODES = defineErrorCodes({
  FAILED_TO_CREATE_USER: "Failed to create user",
  USER_ALREADY_EXISTS: "User already exists.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "User already exists. Use another email.",
  YOU_CANNOT_BAN_YOURSELF: "You cannot ban yourself",
  YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE: "You are not allowed to change users role",
  YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS: "You are not allowed to create users",
  YOU_ARE_NOT_ALLOWED_TO_LIST_USERS: "You are not allowed to list users",
  YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS: "You are not allowed to list users sessions",
  YOU_ARE_NOT_ALLOWED_TO_BAN_USERS: "You are not allowed to ban users",
  YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS: "You are not allowed to impersonate users",
  YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS: "You are not allowed to revoke users sessions",
  YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS: "You are not allowed to delete users",
  YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD: "You are not allowed to set users password",
  BANNED_USER: "You have been banned from this application",
  YOU_ARE_NOT_ALLOWED_TO_GET_USER: "You are not allowed to get user",
  NO_DATA_TO_UPDATE: "No data to update",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS: "You are not allowed to update users",
  YOU_CANNOT_REMOVE_YOURSELF: "You cannot remove yourself"
});

// node_modules/better-auth/dist/shared/better-auth.DDuRjwGK.mjs
var minute2 = 60;
var hour2 = minute2 * 60;
var day2 = hour2 * 24;
var week2 = day2 * 7;
var year2 = day2 * 365.25;

// node_modules/better-auth/dist/plugins/custom-session/index.mjs
var getSessionQuerySchema2 = optional(
  object({
    /**
     * If cookie cache is enabled, it will disable the cache
     * and fetch the session from the database
     */
    disableCookieCache: boolean2().meta({
      description: "Disable cookie cache and fetch session from database"
    }).or(string2().transform((v) => v === "true")).optional(),
    disableRefresh: boolean2().meta({
      description: "Disable session refresh. Useful for checking session status, without updating the session"
    }).optional()
  })
);

// node_modules/better-auth/dist/plugins/captcha/index.mjs
var Providers = {
  CLOUDFLARE_TURNSTILE: "cloudflare-turnstile",
  GOOGLE_RECAPTCHA: "google-recaptcha",
  HCAPTCHA: "hcaptcha",
  CAPTCHAFOX: "captchafox"
};
var siteVerifyMap = {
  [Providers.CLOUDFLARE_TURNSTILE]: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
  [Providers.GOOGLE_RECAPTCHA]: "https://www.google.com/recaptcha/api/siteverify",
  [Providers.HCAPTCHA]: "https://api.hcaptcha.com/siteverify",
  [Providers.CAPTCHAFOX]: "https://api.captchafox.com/siteverify"
};
var EXTERNAL_ERROR_CODES = defineErrorCodes({
  VERIFICATION_FAILED: "Captcha verification failed",
  MISSING_RESPONSE: "Missing CAPTCHA response",
  UNKNOWN_ERROR: "Something went wrong"
});
var INTERNAL_ERROR_CODES = defineErrorCodes({
  MISSING_SECRET_KEY: "Missing secret key",
  SERVICE_UNAVAILABLE: "CAPTCHA service unavailable"
});

// node_modules/better-auth/dist/plugins/device-authorization/index.mjs
object({
  id: string2(),
  deviceCode: string2(),
  userCode: string2(),
  userId: string2().optional(),
  expiresAt: date3(),
  status: string2(),
  lastPolledAt: date3().optional(),
  pollingInterval: number2().optional(),
  clientId: string2().optional(),
  scope: string2().optional()
});
var msStringValueSchema = custom(
  (val) => {
    try {
      ms(val);
    } catch (e) {
      return false;
    }
    return true;
  },
  {
    message: "Invalid time string format. Use formats like '30m', '5s', '1h', etc."
  }
);
var $deviceAuthorizationOptionsSchema = object({
  expiresIn: msStringValueSchema.default("30m").describe(
    "Time in seconds until the device code expires. Use formats like '30m', '5s', '1h', etc."
  ),
  interval: msStringValueSchema.default("5s").describe(
    "Time in seconds between polling attempts. Use formats like '30m', '5s', '1h', etc."
  ),
  deviceCodeLength: number2().int().positive().default(40).describe(
    "Length of the device code to be generated. Default is 40 characters."
  ),
  userCodeLength: number2().int().positive().default(8).describe(
    "Length of the user code to be generated. Default is 8 characters."
  ),
  generateDeviceCode: custom(
    (val) => typeof val === "function",
    {
      message: "generateDeviceCode must be a function that returns a string or a promise that resolves to a string."
    }
  ).optional().describe(
    "Function to generate a device code. If not provided, a default random string generator will be used."
  ),
  generateUserCode: custom(
    (val) => typeof val === "function",
    {
      message: "generateUserCode must be a function that returns a string or a promise that resolves to a string."
    }
  ).optional().describe(
    "Function to generate a user code. If not provided, a default random string generator will be used."
  ),
  validateClient: custom(
    (val) => typeof val === "function",
    {
      message: "validateClient must be a function that returns a boolean or a promise that resolves to a boolean."
    }
  ).optional().describe(
    "Function to validate the client ID. If not provided, no validation will be performed."
  ),
  onDeviceAuthRequest: custom((val) => typeof val === "function", {
    message: "onDeviceAuthRequest must be a function that returns void or a promise that resolves to void."
  }).optional().describe(
    "Function to handle device authorization requests. If not provided, no additional actions will be taken."
  ),
  schema: custom(() => true)
});

// src/middlewares.ts
import * as express from "express";
function SkipBodyParsingMiddleware(basePath = "/api/auth") {
  return (req, res, next) => {
    if (req.baseUrl.startsWith(basePath)) {
      next();
      return;
    }
    express.json()(req, res, (err) => {
      if (err) {
        next(err);
        return;
      }
      express.urlencoded({
        extended: true
      })(req, res, next);
    });
  };
}
__name(SkipBodyParsingMiddleware, "SkipBodyParsingMiddleware");

// src/auth-module.ts
import { APP_GUARD } from "@nestjs/core";
function _ts_decorate3(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d2;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d2 = decorators[i]) r = (c < 3 ? d2(r) : c > 3 ? d2(target, key, r) : d2(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate3, "_ts_decorate");
function _ts_metadata3(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata3, "_ts_metadata");
function _ts_param3(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param3, "_ts_param");
var HOOKS = [
  {
    metadataKey: BEFORE_HOOK_KEY,
    hookType: "before"
  },
  {
    metadataKey: AFTER_HOOK_KEY,
    hookType: "after"
  }
];
var AuthModule = class _AuthModule extends ConfigurableModuleClass {
  static {
    __name(this, "AuthModule");
  }
  discoveryService;
  metadataScanner;
  adapter;
  options;
  logger = new Logger(_AuthModule.name);
  constructor(discoveryService, metadataScanner, adapter, options) {
    super(), this.discoveryService = discoveryService, this.metadataScanner = metadataScanner, this.adapter = adapter, this.options = options;
  }
  onModuleInit() {
    const providers = this.discoveryService.getProviders().filter(({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype));
    const hasHookProviders = providers.length > 0;
    const hooksConfigured = typeof this.options.auth?.options?.hooks === "object";
    if (hasHookProviders && !hooksConfigured) throw new Error("Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options.");
    if (!hooksConfigured) return;
    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods2 = this.metadataScanner.getAllMethodNames(providerPrototype);
      for (const method of methods2) {
        const providerMethod = providerPrototype[method];
        this.setupHooks(providerMethod, provider.instance);
      }
    }
  }
  configure(consumer) {
    const trustedOrigins = this.options.auth.options.trustedOrigins;
    const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);
    if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins,
        methods: [
          "GET",
          "POST",
          "PUT",
          "DELETE"
        ],
        credentials: true
      });
    } else if (trustedOrigins && !this.options.disableTrustedOriginsCors && !isNotFunctionBased) throw new Error("Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true.");
    let basePath = this.options.auth.options.basePath ?? "/api/auth";
    if (!basePath.startsWith("/")) {
      basePath = `/${basePath}`;
    }
    if (basePath.endsWith("/")) {
      basePath = basePath.slice(0, -1);
    }
    if (!this.options.disableBodyParser) {
      consumer.apply(SkipBodyParsingMiddleware(basePath)).forRoutes("*path");
    }
    const handler = toNodeHandler2(this.options.auth);
    this.adapter.httpAdapter.getInstance().use(`${basePath}/*path`, (req, res) => {
      return handler(req, res);
    });
    this.logger.log(`AuthModule initialized BetterAuth on '${basePath}/*'`);
  }
  setupHooks(providerMethod, providerClass) {
    if (!this.options.auth.options.hooks) return;
    for (const { metadataKey, hookType } of HOOKS) {
      const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
      if (!hasHook) continue;
      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);
      const originalHook = this.options.auth.options.hooks[hookType];
      this.options.auth.options.hooks[hookType] = createAuthMiddleware(async (ctx) => {
        if (originalHook) {
          await originalHook(ctx);
        }
        if (hookPath && hookPath !== ctx.path) return;
        await providerMethod.apply(providerClass, [
          ctx
        ]);
      });
    }
  }
  static forRootAsync(options) {
    const forRootAsyncResult = super.forRootAsync(options);
    return {
      ...super.forRootAsync(options),
      providers: [
        ...forRootAsyncResult.providers ?? [],
        ...!options.disableGlobalAuthGuard ? [
          {
            provide: APP_GUARD,
            useClass: AuthGuard
          }
        ] : []
      ]
    };
  }
  static forRoot(arg1, arg2) {
    const normalizedOptions = typeof arg1 === "object" && arg1 !== null && "auth" in arg1 ? arg1 : {
      ...arg2 ?? {},
      auth: arg1
    };
    const forRootResult = super.forRoot(normalizedOptions);
    return {
      ...forRootResult,
      providers: [
        ...forRootResult.providers ?? [],
        ...!normalizedOptions.disableGlobalAuthGuard ? [
          {
            provide: APP_GUARD,
            useClass: AuthGuard
          }
        ] : []
      ]
    };
  }
};
AuthModule = _ts_decorate3([
  Module({
    imports: [
      DiscoveryModule
    ],
    providers: [
      AuthService
    ],
    exports: [
      AuthService
    ]
  }),
  _ts_param3(0, Inject3(DiscoveryService)),
  _ts_param3(1, Inject3(MetadataScanner)),
  _ts_param3(2, Inject3(HttpAdapterHost)),
  _ts_param3(3, Inject3(MODULE_OPTIONS_TOKEN)),
  _ts_metadata3("design:type", Function),
  _ts_metadata3("design:paramtypes", [
    typeof DiscoveryService === "undefined" ? Object : DiscoveryService,
    typeof MetadataScanner === "undefined" ? Object : MetadataScanner,
    typeof HttpAdapterHost === "undefined" ? Object : HttpAdapterHost,
    typeof AuthModuleOptions === "undefined" ? Object : AuthModuleOptions
  ])
], AuthModule);
export {
  AFTER_HOOK_KEY,
  AUTH_MODULE_OPTIONS_KEY,
  AfterHook,
  AllowAnonymous,
  AuthGuard,
  AuthModule,
  AuthService,
  BEFORE_HOOK_KEY,
  BeforeHook,
  HOOK_KEY,
  Hook,
  Optional,
  OptionalAuth,
  Permissions,
  Public,
  Roles,
  Session
};
/*! Bundled license information:

@noble/ciphers/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
//# sourceMappingURL=index.js.map