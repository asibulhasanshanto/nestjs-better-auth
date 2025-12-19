export * from "./decorators.ts";
export * from "./auth-service.ts";
export * from "./auth-guard.ts";
export * from "./auth-module.ts";
export * from "./symbols.ts";
export * from "./permission-service.interface.ts";

// Re-export commonly used better-auth functions so they get bundled
// This avoids ESM/CJS issues when consuming from CommonJS projects
export { betterAuth } from "better-auth";
export type { Auth, BetterAuthOptions } from "better-auth";
export { prismaAdapter } from "better-auth/adapters/prisma";
export { createAuthMiddleware, bearer } from "better-auth/plugins";
export { toNodeHandler, fromNodeHeaders } from "better-auth/node";
