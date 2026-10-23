from pathlib import Path

main_path = Path(__file__).resolve().parent.parent / "backend" / "app" / "main.py"
source = main_path.read_text(encoding="utf-8")
old_import = "from app.core.security import get_password_hash"
new_import = "from app.core.security import get_password_hash, verify_password"
old_block = '''            if initial_admin is None:
                db.add(User(
                    username=settings.ADMIN_USERNAME,
                    email=f"{settings.ADMIN_USERNAME}@localhost.invalid",
                    hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                    role=UserRole.admin,
                ))'''
new_block = '''            if initial_admin is None:
                db.add(User(
                    username=settings.ADMIN_USERNAME,
                    email=f"{settings.ADMIN_USERNAME}@localhost.invalid",
                    hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                    role=UserRole.admin,
                ))
            elif verify_password(settings.ADMIN_PASSWORD, initial_admin.hashed_password):
                # Promote only the account whose existing password matches the
                # operator-configured admin credential in backend/.env.
                initial_admin.role = UserRole.admin'''
if old_import not in source or old_block not in source:
    raise SystemExit("Expected admin seeding code was not found; backend file was not changed.")
source = source.replace(old_import, new_import, 1).replace(old_block, new_block, 1)
main_path.write_text(source, encoding="utf-8")
print("Configured admin account can now be promoted only after its password matches the server-side admin credential.")
