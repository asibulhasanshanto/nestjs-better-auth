'use strict';

const common = require('@nestjs/common');
const core = require('@nestjs/core');
const node = require('better-auth/node');
const websockets = require('@nestjs/websockets');
const plugins = require('better-auth/plugins');
const express = require('express');

function _interopNamespaceCompat(e) {
  if (e && typeof e === 'object' && 'default' in e) return e;
  const n = Object.create(null);
  if (e) {
    for (const k in e) {
      n[k] = e[k];
    }
  }
  n.default = e;
  return n;
}

const express__namespace = /*#__PURE__*/_interopNamespaceCompat(express);

const BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK");
const AFTER_HOOK_KEY = Symbol("AFTER_HOOK");
const HOOK_KEY = Symbol("HOOK");
const AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS");

function getRequestFromContext(context) {
  return context.switchToHttp().getRequest();
}

const AllowAnonymous = () => common.SetMetadata("PUBLIC", true);
const OptionalAuth = () => common.SetMetadata("OPTIONAL", true);
const Roles = (roles) => common.SetMetadata("ROLES", roles);
const Permissions = (permissions) => common.SetMetadata("PERMISSIONS", permissions);
const Public = AllowAnonymous;
const Optional = OptionalAuth;
const Session = common.createParamDecorator((_data, context) => {
  const request = getRequestFromContext(context);
  return request.session;
});
const BeforeHook = (path) => common.SetMetadata(BEFORE_HOOK_KEY, path);
const AfterHook = (path) => common.SetMetadata(AFTER_HOOK_KEY, path);
const Hook = () => common.SetMetadata(HOOK_KEY, true);

const MODULE_OPTIONS_TOKEN = Symbol("AUTH_MODULE_OPTIONS");
const { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } = new common.ConfigurableModuleBuilder({
  optionsInjectionToken: MODULE_OPTIONS_TOKEN
}).setClassMethodName("forRoot").setExtras(
  {
    isGlobal: true,
    disableTrustedOriginsCors: false,
    disableBodyParser: false,
    disableGlobalAuthGuard: false
  },
  (def, extras) => {
    return {
      ...def,
      exports: [MODULE_OPTIONS_TOKEN],
      global: extras.isGlobal
    };
  }
).build();

var __getOwnPropDesc$2 = Object.getOwnPropertyDescriptor;
var __decorateClass$2 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$2(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$2 = (index, decorator) => (target, key) => decorator(target, key, index);
exports.AuthService = class AuthService {
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
exports.AuthService = __decorateClass$2([
  __decorateParam$2(0, common.Inject(MODULE_OPTIONS_TOKEN))
], exports.AuthService);

var __getOwnPropDesc$1 = Object.getOwnPropertyDescriptor;
var __decorateClass$1 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$1(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$1 = (index, decorator) => (target, key) => decorator(target, key, index);
const AuthContextErrorMap = {
  http: {
    UNAUTHORIZED: (args) => new common.UnauthorizedException(
      args ?? {
        code: "UNAUTHORIZED",
        message: "Unauthorized"
      }
    ),
    FORBIDDEN: (args) => new common.ForbiddenException(
      args ?? {
        code: "FORBIDDEN",
        message: "Insufficient permissions"
      }
    )
  },
  ws: {
    UNAUTHORIZED: (args) => new websockets.WsException(args ?? "UNAUTHORIZED"),
    FORBIDDEN: (args) => new websockets.WsException(args ?? "FORBIDDEN")
  },
  rpc: {
    UNAUTHORIZED: () => new Error("UNAUTHORIZED"),
    FORBIDDEN: () => new Error("FORBIDDEN")
  }
};
exports.AuthGuard = class AuthGuard {
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
      headers: node.fromNodeHeaders(
        request.headers || request?.handshake?.headers || []
      )
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
    const requiredPermissions = this.reflector.getAllAndOverride(
      "PERMISSIONS",
      [context.getHandler(), context.getClass()]
    );
    if (requiredPermissions && requiredPermissions.length > 0) {
      if (!this.permissionService) {
        throw new Error(
          "PermissionService is required when using @Permissions() decorator. Please provide a PermissionService implementation."
        );
      }
      const userId = session.user.id;
      const hasAllPermissions = await this.permissionService.hasAllPermissions(
        userId,
        requiredPermissions
      );
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
        hasRole = userRole.some((role) => requiredRoles.includes(role));
      } else if (typeof userRole === "string") {
        hasRole = userRole.split(",").some((role) => requiredRoles.includes(role));
      }
      if (!hasRole) throw AuthContextErrorMap[ctxType].FORBIDDEN();
    }
    return true;
  }
};
exports.AuthGuard = __decorateClass$1([
  common.Injectable(),
  __decorateParam$1(0, common.Inject(core.Reflector)),
  __decorateParam$1(1, common.Inject(MODULE_OPTIONS_TOKEN)),
  __decorateParam$1(2, common.Optional()),
  __decorateParam$1(2, common.Inject("PERMISSION_SERVICE"))
], exports.AuthGuard);

function SkipBodyParsingMiddleware(basePath = "/api/auth") {
  return (req, res, next) => {
    if (req.baseUrl.startsWith(basePath)) {
      next();
      return;
    }
    express__namespace.json()(req, res, (err) => {
      if (err) {
        next(err);
        return;
      }
      express__namespace.urlencoded({ extended: true })(req, res, next);
    });
  };
}

var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __decorateClass = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam = (index, decorator) => (target, key) => decorator(target, key, index);
const HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" }
];
exports.AuthModule = class AuthModule extends ConfigurableModuleClass {
  constructor(discoveryService, metadataScanner, adapter, options) {
    super();
    this.discoveryService = discoveryService;
    this.metadataScanner = metadataScanner;
    this.adapter = adapter;
    this.options = options;
  }
  logger = new common.Logger(exports.AuthModule.name);
  onModuleInit() {
    const providers = this.discoveryService.getProviders().filter(
      ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype)
    );
    const hasHookProviders = providers.length > 0;
    const hooksConfigured = typeof this.options.auth?.options?.hooks === "object";
    if (hasHookProviders && !hooksConfigured)
      throw new Error(
        "Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options."
      );
    if (!hooksConfigured) return;
    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
      for (const method of methods) {
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
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
      });
    } else if (trustedOrigins && !this.options.disableTrustedOriginsCors && !isNotFunctionBased)
      throw new Error(
        "Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true."
      );
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
    const handler = node.toNodeHandler(this.options.auth);
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
      this.options.auth.options.hooks[hookType] = plugins.createAuthMiddleware(
        async (ctx) => {
          if (originalHook) {
            await originalHook(ctx);
          }
          if (hookPath && hookPath !== ctx.path) return;
          await providerMethod.apply(providerClass, [ctx]);
        }
      );
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
            provide: core.APP_GUARD,
            useClass: exports.AuthGuard
          }
        ] : []
      ]
    };
  }
  static forRoot(arg1, arg2) {
    const normalizedOptions = typeof arg1 === "object" && arg1 !== null && "auth" in arg1 ? arg1 : { ...arg2 ?? {}, auth: arg1 };
    const forRootResult = super.forRoot(normalizedOptions);
    return {
      ...forRootResult,
      providers: [
        ...forRootResult.providers ?? [],
        ...!normalizedOptions.disableGlobalAuthGuard ? [
          {
            provide: core.APP_GUARD,
            useClass: exports.AuthGuard
          }
        ] : []
      ]
    };
  }
};
exports.AuthModule = __decorateClass([
  common.Module({
    imports: [core.DiscoveryModule],
    providers: [exports.AuthService],
    exports: [exports.AuthService]
  }),
  __decorateParam(0, common.Inject(core.DiscoveryService)),
  __decorateParam(1, common.Inject(core.MetadataScanner)),
  __decorateParam(2, common.Inject(core.HttpAdapterHost)),
  __decorateParam(3, common.Inject(MODULE_OPTIONS_TOKEN))
], exports.AuthModule);

exports.AFTER_HOOK_KEY = AFTER_HOOK_KEY;
exports.AUTH_MODULE_OPTIONS_KEY = AUTH_MODULE_OPTIONS_KEY;
exports.AfterHook = AfterHook;
exports.AllowAnonymous = AllowAnonymous;
exports.BEFORE_HOOK_KEY = BEFORE_HOOK_KEY;
exports.BeforeHook = BeforeHook;
exports.HOOK_KEY = HOOK_KEY;
exports.Hook = Hook;
exports.Optional = Optional;
exports.OptionalAuth = OptionalAuth;
exports.Permissions = Permissions;
exports.Public = Public;
exports.Roles = Roles;
exports.Session = Session;
