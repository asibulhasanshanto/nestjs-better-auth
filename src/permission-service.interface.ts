/**
 * Interface for permission service implementations.
 * Users should implement this interface with their own database logic.
 */
export interface IPermissionService {
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