import * as _nestjs_common from '@nestjs/common';
import { CustomDecorator, createParamDecorator, NestModule, OnModuleInit, MiddlewareConsumer, DynamicModule, CanActivate, ExecutionContext } from '@nestjs/common';
import { createAuthMiddleware, getSession } from 'better-auth/api';
import { Auth as Auth$1 } from 'better-auth';
export { Auth, BetterAuthOptions, betterAuth } from 'better-auth';
import { DiscoveryService, MetadataScanner, HttpAdapterHost, Reflector } from '@nestjs/core';
export { prismaAdapter } from 'better-auth/adapters/prisma';
export { bearer, createAuthMiddleware } from 'better-auth/plugins';
export { fromNodeHeaders, toNodeHandler } from 'better-auth/node';

/**
 * Allows unauthenticated (anonymous) access to a route or controller.
 * When applied, the AuthGuard will not perform authentication checks.
 */
declare const AllowAnonymous: () => CustomDecorator<string>;
/**
 * Marks a route or controller as having optional authentication.
 * When applied, the AuthGuard allows the request to proceed
 * even if no session is present.
 */
declare const OptionalAuth: () => CustomDecorator<string>;
/**
 * Specifies the roles required to access a route or controller.
 * The AuthGuard will check if the authenticated user's roles
 * include at least one of the specified roles.
 * @param roles - The roles required for access
 */
declare const Roles: (roles: string[]) => CustomDecorator;
/**
 * Specifies the permissions required to access a route or controller.
 * The AuthGuard will check if the authenticated user has all the specified permissions.
 * Permissions are fetched dynamically from the database via PermissionService.
 * @param permissions - The permissions required for access
 */
declare const Permissions: (permissions: string[]) => CustomDecorator;
/**
 * @deprecated Use AllowAnonymous() instead.
 */
declare const Public: () => CustomDecorator<string>;
/**
 * @deprecated Use OptionalAuth() instead.
 */
declare const Optional: () => CustomDecorator<string>;
/**
 * Parameter decorator that extracts the user session from the request.
 * Provides easy access to the authenticated user's session data in controller methods.
 * Works with both HTTP and GraphQL execution contexts.
 */
declare const Session: ReturnType<typeof createParamDecorator>;
/**
 * Represents the context object passed to hooks.
 * This type is derived from the parameters of the createAuthMiddleware function.
 */
type AuthHookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
/**
 * Registers a method to be executed before a specific auth route is processed.
 * @param path - The auth route path that triggers this hook (must start with '/')
 */
declare const BeforeHook: (path?: `/${string}`) => CustomDecorator<symbol>;
/**
 * Registers a method to be executed after a specific auth route is processed.
 * @param path - The auth route path that triggers this hook (must start with '/')
 */
declare const AfterHook: (path?: `/${string}`) => CustomDecorator<symbol>;
/**
 * Class decorator that marks a provider as containing hook methods.
 * Must be applied to classes that use BeforeHook or AfterHook decorators.
 */
declare const Hook: () => ClassDecorator;

type Auth = any;
/**
 * NestJS module that integrates the Auth library with NestJS applications.
 * Provides authentication middleware, hooks, and exception handling.
 */
declare class AuthModule extends ConfigurableModuleClass implements NestModule, OnModuleInit {
    private readonly discoveryService;
    private readonly metadataScanner;
    private readonly adapter;
    private readonly options;
    private readonly logger;
    constructor(discoveryService: DiscoveryService, metadataScanner: MetadataScanner, adapter: HttpAdapterHost, options: AuthModuleOptions);
    onModuleInit(): void;
    configure(consumer: MiddlewareConsumer): void;
    private setupHooks;
    static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule;
    static forRoot(options: typeof OPTIONS_TYPE): DynamicModule;
    /**
     * @deprecated Use the object-based signature: AuthModule.forRoot({ auth, ...options })
     */
    static forRoot(auth: Auth, options?: Omit<typeof OPTIONS_TYPE, "auth">): DynamicModule;
}

type AuthModuleOptions<A = Auth> = {
    auth: A;
    disableTrustedOriginsCors?: boolean;
    disableBodyParser?: boolean;
    disableGlobalAuthGuard?: boolean;
};
declare const ConfigurableModuleClass: _nestjs_common.ConfigurableModuleCls<AuthModuleOptions<any>, "forRoot", "create", {
    isGlobal: boolean;
    disableTrustedOriginsCors: boolean;
    disableBodyParser: boolean;
    disableGlobalAuthGuard: boolean;
}>;
declare const OPTIONS_TYPE: AuthModuleOptions<any> & Partial<{
    isGlobal: boolean;
    disableTrustedOriginsCors: boolean;
    disableBodyParser: boolean;
    disableGlobalAuthGuard: boolean;
}>;
declare const ASYNC_OPTIONS_TYPE: _nestjs_common.ConfigurableModuleAsyncOptions<AuthModuleOptions<any>, "create"> & Partial<{
    isGlobal: boolean;
    disableTrustedOriginsCors: boolean;
    disableBodyParser: boolean;
    disableGlobalAuthGuard: boolean;
}>;

/**
 * NestJS service that provides access to the Better Auth instance
 * Use generics to support auth instances extended by plugins
 */
declare class AuthService<T extends {
    api: T["api"];
} = Auth$1> {
    private readonly options;
    constructor(options: AuthModuleOptions<T>);
    /**
     * Returns the API endpoints provided by the auth instance
     */
    get api(): T["api"];
    /**
     * Returns the complete auth instance
     * Access this for plugin-specific functionality
     */
    get instance(): T;
}

/**
 * Interface for permission service implementations.
 * Users should implement this interface with their own database logic.
 */
interface IPermissionService {
    /**
     * Get all permissions for a user based on their user ID
     * @param userId - The user ID
     * @returns Array of permission strings
     */
    getUserPermissions(userId: string): Promise<string[]>;
    /**
     * Get all permissions for roles
     * @param roles - Array of role names
     * @returns Array of permission strings
     */
    getPermissionsForRoles(roles: string[]): Promise<string[]>;
    /**
     * Check if user has a specific permission
     * @param userId - The user ID
     * @param permission - The permission to check
     * @returns True if user has the permission
     */
    hasPermission(userId: string, permission: string): Promise<boolean>;
    /**
     * Check if user has all specified permissions
     * @param userId - The user ID
     * @param permissions - Array of permissions to check
     * @returns True if user has all permissions
     */
    hasAllPermissions(userId: string, permissions: string[]): Promise<boolean>;
}

/**
 * Type representing a valid user session after authentication
 * Excludes null and undefined values from the session return type
 */
type BaseUserSession = NonNullable<Awaited<ReturnType<ReturnType<typeof getSession>>>>;
type UserSession = BaseUserSession & {
    user: BaseUserSession["user"] & {
        role?: string | string[];
    };
};
/**
 * NestJS guard that handles authentication for protected routes
 * Can be configured with @AllowAnonymous() or @OptionalAuth() decorators to modify authentication behavior
 * Supports permission-based access control when PermissionService is provided
 */
declare class AuthGuard implements CanActivate {
    private readonly reflector;
    private readonly options;
    private readonly permissionService?;
    constructor(reflector: Reflector, options: AuthModuleOptions, permissionService?: IPermissionService | undefined);
    /**
     * Validates if the current request is authenticated
     * Attaches session and user information to the request object
     * Supports HTTP, GraphQL and WebSocket execution contexts
     * @param context - The execution context of the current request
     * @returns True if the request is authorized to proceed, throws an error otherwise
     */
    canActivate(context: ExecutionContext): Promise<boolean>;
}

declare const BEFORE_HOOK_KEY: symbol;
declare const AFTER_HOOK_KEY: symbol;
declare const HOOK_KEY: symbol;
declare const AUTH_MODULE_OPTIONS_KEY: symbol;

export { AFTER_HOOK_KEY, AUTH_MODULE_OPTIONS_KEY, AfterHook, AllowAnonymous, AuthGuard, type AuthHookContext, AuthModule, AuthService, BEFORE_HOOK_KEY, type BaseUserSession, BeforeHook, HOOK_KEY, Hook, type IPermissionService, Optional, OptionalAuth, Permissions, Public, Roles, Session, type UserSession };
