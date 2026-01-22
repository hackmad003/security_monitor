"""
Credential Migration Script
Migrates credentials from plaintext targets.yaml to secure encrypted storage
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from src.utils.config import Config
from src.utils.secure_credentials import SecureCredentialStore


def migrate_credentials():
    """Migrate credentials from targets.yaml to secure storage"""
    
    print("=" * 70)
    print("CREDENTIAL MIGRATION TOOL")
    print("=" * 70)
    print("\nThis tool will migrate credentials from plaintext targets.yaml")
    print("to encrypted secure storage.\n")
    
    # Locate targets.yaml
    targets_path = Path(__file__).parent.parent / "config" / "app" / "targets.yaml"
    
    if not targets_path.exists():
        print("❌ Error: targets.yaml not found at:", targets_path)
        return
    
    # Load targets.yaml
    print(f"📁 Reading credentials from: {targets_path}")
    try:
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error reading targets.yaml: {e}")
        return
    
    if not targets_data or 'targets' not in targets_data:
        print("⚠️  No targets found in targets.yaml")
        return
    
    targets = targets_data.get('targets', [])
    if not targets:
        print("⚠️  No targets to migrate")
        return
    
    print(f"\n✓ Found {len(targets)} target(s) to migrate:\n")
    
    # Display targets
    for i, target in enumerate(targets, 1):
        name = target.get('name', 'unnamed')
        hostname = target.get('hostname', 'N/A')
        has_creds = 'credentials' in target
        print(f"  {i}. {name} ({hostname}) - {'✓ Has credentials' if has_creds else '✗ No credentials'}")
    
    # Confirm migration
    print("\n" + "-" * 70)
    response = input("\nProceed with migration? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        print("\n❌ Migration cancelled")
        return
    
    # Initialize secure credential store
    config = Config()
    store = config.credential_store
    
    # Migrate each target
    print("\n" + "=" * 70)
    print("MIGRATING CREDENTIALS")
    print("=" * 70 + "\n")
    
    migrated = 0
    skipped = 0
    
    for target in targets:
        name = target.get('name')
        if not name:
            print("⚠️  Skipping target without name")
            skipped += 1
            continue
        
        creds = target.get('credentials', {})
        username = creds.get('username')
        password = creds.get('password')
        
        if not username or not password:
            print(f"⚠️  Skipping {name}: Missing credentials")
            skipped += 1
            continue
        
        try:
            store.store_credentials(name, username, password)
            print(f"✓ Migrated credentials for: {name}")
            migrated += 1
        except Exception as e:
            print(f"❌ Error migrating {name}: {e}")
            skipped += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("MIGRATION COMPLETE")
    print("=" * 70)
    print(f"\n✓ Successfully migrated: {migrated} target(s)")
    if skipped > 0:
        print(f"⚠️  Skipped: {skipped} target(s)")
    
    # Show storage location
    storage_dir = store.storage_dir
    print(f"\n📁 Credentials stored in: {storage_dir}")
    print(f"   - Encryption key: {store.key_file}")
    print(f"   - Encrypted credentials: {store.creds_file}")
    
    # Backup recommendation
    print("\n" + "-" * 70)
    print("⚠️  IMPORTANT: NEXT STEPS")
    print("-" * 70)
    print("\n1. BACKUP: Create a backup of your targets.yaml file")
    print(f"   Command: cp {targets_path} {targets_path}.backup")
    print("\n2. VERIFY: Test that credentials work with secure storage")
    print("   Run your monitoring tool to verify access")
    print("\n3. REMOVE: Once verified, remove credentials from targets.yaml")
    print("   - Keep the target definitions (name, hostname, etc.)")
    print("   - Remove only the 'credentials' section")
    print("\n4. SECURE: Ensure encryption key file has proper permissions")
    print(f"   The key file should be readable only by you: {store.key_file}")
    
    print("\n" + "=" * 70)
    
    # Offer to create .env template
    print("\n💡 TIP: You can also use environment variables for credentials")
    print("   Format: <TARGET_NAME>_USERNAME and <TARGET_NAME>_PASSWORD")
    print("   Example: SERVER01_USERNAME=Administrator")
    
    response = input("\nCreate .env.example template? (yes/no): ").strip().lower()
    
    if response in ['yes', 'y']:
        create_env_template(targets)
        print("✓ Created .env.example template")


def create_env_template(targets):
    """Create .env.example template file"""
    env_path = Path(__file__).parent.parent / ".env.example"
    
    lines = [
        "# Security Monitor Environment Variables",
        "# Copy this file to .env and fill in your values",
        "",
        "# MongoDB Configuration",
        "# MONGODB_URI=mongodb://localhost:27017/",
        "# MONGODB_DATABASE=security_monitor",
        "",
        "# Email Configuration",
        "# EMAIL_ENABLED=false",
        "# SMTP_SERVER=smtp.gmail.com",
        "# SMTP_PORT=587",
        "# SENDER_EMAIL=your-email@example.com",
        "# SENDER_PASSWORD=your-app-password",
        "# RECIPIENT_EMAILS=recipient1@example.com,recipient2@example.com",
        "",
        "# Splunk Configuration",
        "# SPLUNK_ENABLED=false",
        "# SPLUNK_HEC_URL=https://localhost:8088/services/collector/event",
        "# SPLUNK_HEC_TOKEN=your-token-here",
        "# SPLUNK_INDEX=main",
        "# SPLUNK_VERIFY_SSL=true",
        "",
        "# Detection Configuration",
        "# BRUTE_FORCE_THRESHOLD=5",
        "# ALERT_RESET_INTERVAL_HOURS=1",
        "",
        "# Target Credentials (Alternative to secure storage)",
        "# Format: <TARGET_NAME>_USERNAME and <TARGET_NAME>_PASSWORD",
        ""
    ]
    
    for target in targets:
        name = target.get('name', '').upper().replace('-', '_').replace('.', '_')
        if name:
            lines.append(f"# {name}_USERNAME=Administrator")
            lines.append(f"# {name}_PASSWORD=SecurePassword123!")
            lines.append("")
    
    lines.append("# JWT Authentication (for API)")
    lines.append("# JWT_SECRET_KEY=change-this-to-a-random-secret-key")
    lines.append("# JWT_ALGORITHM=HS256")
    lines.append("# JWT_EXPIRATION_MINUTES=30")
    lines.append("")
    
    env_path.write_text('\n'.join(lines))


if __name__ == "__main__":
    try:
        migrate_credentials()
    except KeyboardInterrupt:
        print("\n\n❌ Migration cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
