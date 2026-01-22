"""
User Management Script
Create, update, and manage user accounts for the security monitor
"""

import sys
from pathlib import Path
import getpass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.user_store import UserStore


def print_menu():
    """Print main menu"""
    print("\n" + "=" * 70)
    print("USER MANAGEMENT")
    print("=" * 70)
    print("\n1. Create User")
    print("2. List Users")
    print("3. Change Password")
    print("4. Update User Roles")
    print("5. Enable/Disable User")
    print("6. Delete User")
    print("7. Exit")
    print("\n" + "-" * 70)


def create_user(store: UserStore):
    """Create a new user"""
    print("\n" + "=" * 70)
    print("CREATE USER")
    print("=" * 70 + "\n")
    
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Confirm Password: ")
    
    if password != password_confirm:
        print("❌ Passwords do not match")
        return
    
    if len(password) < 8:
        print("❌ Password must be at least 8 characters")
        return
    
    full_name = input("Full Name (optional): ").strip()
    email = input("Email (optional): ").strip()
    
    print("\nRoles (comma-separated, e.g., admin,viewer):")
    print("  - admin: Full access to all features")
    print("  - viewer: Read-only access")
    roles_input = input("Roles [viewer]: ").strip()
    
    if roles_input:
        roles = [r.strip() for r in roles_input.split(',')]
    else:
        roles = ['viewer']
    
    # Create user
    if store.create_user(username, password, full_name, email, roles):
        print(f"\n✓ User created successfully: {username}")
    else:
        print(f"\n❌ Failed to create user (username may already exist)")


def list_users(store: UserStore):
    """List all users"""
    print("\n" + "=" * 70)
    print("USER LIST")
    print("=" * 70 + "\n")
    
    users = store.list_users()
    
    if not users:
        print("No users found")
        return
    
    for user in users:
        status = "✓ Enabled" if user.get('enabled', True) else "✗ Disabled"
        roles = ', '.join(user.get('roles', []))
        print(f"  • {user['username']:<20} [{status}]")
        print(f"    Roles: {roles}")
        if user.get('full_name'):
            print(f"    Name: {user['full_name']}")
        if user.get('email'):
            print(f"    Email: {user['email']}")
        print()


def change_password(store: UserStore):
    """Change user password"""
    print("\n" + "=" * 70)
    print("CHANGE PASSWORD")
    print("=" * 70 + "\n")
    
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    password = getpass.getpass("New Password: ")
    password_confirm = getpass.getpass("Confirm Password: ")
    
    if password != password_confirm:
        print("❌ Passwords do not match")
        return
    
    if len(password) < 8:
        print("❌ Password must be at least 8 characters")
        return
    
    if store.change_password(username, password):
        print(f"\n✓ Password changed successfully for: {username}")
    else:
        print(f"\n❌ Failed to change password (user may not exist)")


def update_roles(store: UserStore):
    """Update user roles"""
    print("\n" + "=" * 70)
    print("UPDATE USER ROLES")
    print("=" * 70 + "\n")
    
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    user = store.get_user(username)
    if not user:
        print(f"❌ User not found: {username}")
        return
    
    print(f"\nCurrent roles: {', '.join(user.get('roles', []))}")
    print("\nNew roles (comma-separated):")
    roles_input = input("Roles: ").strip()
    
    if not roles_input:
        print("❌ Roles cannot be empty")
        return
    
    roles = [r.strip() for r in roles_input.split(',')]
    
    if store.update_user(username, roles=roles):
        print(f"\n✓ Roles updated successfully for: {username}")
    else:
        print(f"\n❌ Failed to update roles")


def toggle_user(store: UserStore):
    """Enable or disable user"""
    print("\n" + "=" * 70)
    print("ENABLE/DISABLE USER")
    print("=" * 70 + "\n")
    
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    user = store.get_user(username)
    if not user:
        print(f"❌ User not found: {username}")
        return
    
    current_status = "Enabled" if user.get('enabled', True) else "Disabled"
    print(f"\nCurrent status: {current_status}")
    
    action = input("Enable or Disable? (e/d): ").strip().lower()
    
    if action not in ['e', 'd']:
        print("❌ Invalid choice")
        return
    
    enabled = (action == 'e')
    
    if store.update_user(username, enabled=enabled):
        status = "enabled" if enabled else "disabled"
        print(f"\n✓ User {status} successfully: {username}")
    else:
        print(f"\n❌ Failed to update user status")


def delete_user(store: UserStore):
    """Delete a user"""
    print("\n" + "=" * 70)
    print("DELETE USER")
    print("=" * 70 + "\n")
    
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    user = store.get_user(username)
    if not user:
        print(f"❌ User not found: {username}")
        return
    
    print(f"\n⚠️  WARNING: You are about to delete user: {username}")
    confirm = input("Type 'DELETE' to confirm: ").strip()
    
    if confirm != 'DELETE':
        print("❌ Deletion cancelled")
        return
    
    if store.delete_user(username):
        print(f"\n✓ User deleted successfully: {username}")
    else:
        print(f"\n❌ Failed to delete user (may be the last admin)")


def main():
    """Main function"""
    store = UserStore()
    
    while True:
        print_menu()
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            create_user(store)
        elif choice == '2':
            list_users(store)
        elif choice == '3':
            change_password(store)
        elif choice == '4':
            update_roles(store)
        elif choice == '5':
            toggle_user(store)
        elif choice == '6':
            delete_user(store)
        elif choice == '7':
            print("\n✓ Goodbye!")
            break
        else:
            print("\n❌ Invalid option")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
