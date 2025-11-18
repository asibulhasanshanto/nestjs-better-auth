import type { ExecutionContext } from "@nestjs/common";

/**
 * Extracts the request object from either HTTP, GraphQL or WebSocket execution context
 * @param context - The execution context
 * @returns The request object
 */
export function getRequestFromContext(context: ExecutionContext) {
  return context.switchToHttp().getRequest();
}
