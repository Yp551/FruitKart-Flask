# FruitKart

FruitKart is a Flask and SQLite fruit store with user accounts, shopping cart, Cash on Delivery demo checkout, order history and a protected admin dashboard.

## Windows setup

```powershell
cd C:\Users\DELL\Desktop\fruitkarts
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Environment variables

Copy `.env.example` to `.env` if needed and set `SECRET_KEY` to a random secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

The application loads the database at `database.db` and initializes missing tables automatically. Existing users and products are preserved.

## Existing administrator

The existing administrator account is preserved and its password is securely hashed during startup. Use the administrator password already configured for the existing account. Change it immediately after the first successful login. Do not commit administrator passwords to this repository.

## Testing

1. Open the homepage.
2. Register a new user.
3. Log in.
4. Add a fruit to the cart.
5. Update quantity, then remove an item.
6. Add an item again and place a Cash on Delivery demo order.
7. Open My Orders and verify the order detail.
8. Log out.
9. Log in as admin.
10. Add, edit and delete a product.
11. Change an order status.
12. Open `/admin` while logged out and as a normal user; both must be denied.
