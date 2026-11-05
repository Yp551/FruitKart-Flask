import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                image TEXT NOT NULL
            )
        """)

        # Add safe columns for existing databases without replacing product data.
        product_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(products)")
        }
        if "stock" not in product_columns:
            connection.execute(
                "ALTER TABLE products ADD COLUMN stock INTEGER NOT NULL DEFAULT 100"
            )
        if "category" not in product_columns:
            connection.execute(
                "ALTER TABLE products ADD COLUMN category TEXT NOT NULL DEFAULT 'Fresh Fruit'"
            )
        if "description" not in product_columns:
            connection.execute(
                "ALTER TABLE products ADD COLUMN description TEXT NOT NULL DEFAULT ''"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS cart_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
                UNIQUE(user_id, product_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_number TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                customer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                total REAL NOT NULL CHECK(total >= 0),
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                product_name TEXT NOT NULL,
                price REAL NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY(product_id) REFERENCES products(id)
            )
        """)

        # Existing unhashed passwords are upgraded once; new passwords are hashed at registration.
        for user in connection.execute("SELECT id, password FROM users").fetchall():
            password = user["password"] or ""
            if not password.startswith(("pbkdf2:", "scrypt:")):
                connection.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), user["id"])
                )


init_db()


@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.before_request
def csrf_check():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        submitted = request.form.get("csrf_token")
        if not submitted or submitted != session.get("csrf_token"):
            abort(400, description="Invalid or missing CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in as an administrator.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def template_helpers():
    return {
        "csrf_token": session.get("csrf_token"),
        "cart_count": get_cart_count()
    }


def get_cart_count():
    user_id = session.get("user_id")
    if not user_id:
        return 0
    with get_db() as connection:
        row = connection.execute(
            "SELECT COALESCE(SUM(quantity), 0) AS count FROM cart_items WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        return row["count"]


@app.route("/")
def home():
    with get_db() as connection:
        products = connection.execute(
            "SELECT * FROM products ORDER BY id DESC"
        ).fetchall()
    return render_template("index.html", products=products)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(name) < 2:
            flash("Please enter your full name.", "danger")
        elif "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            with get_db() as connection:
                existing = connection.execute(
                    "SELECT id FROM users WHERE email = ?", (email,)
                ).fetchone()
                if existing:
                    flash("An account with this email already exists.", "danger")
                else:
                    connection.execute(
                        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'user')",
                        (name, email, generate_password_hash(password))
                    )
                    flash("Registration successful. Please log in.", "success")
                    return redirect(url_for("login"))
    return render_template("login.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["csrf_token"] = secrets.token_hex(32)
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["role"] = user["role"]
            flash("Welcome, " + user["name"] + "!", "success")
            if user["role"] == "admin":
                return redirect(url_for("admin"))
            return redirect(url_for("home"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html", mode="login")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/cart")
@login_required
def cart():
    with get_db() as connection:
        items = connection.execute("""
            SELECT cart_items.id, cart_items.quantity, products.id AS product_id,
                   products.name, products.price, products.image, products.stock
            FROM cart_items
            JOIN products ON products.id = cart_items.product_id
            WHERE cart_items.user_id = ?
            ORDER BY cart_items.id
        """, (session["user_id"],)).fetchall()
    total = sum(item["price"] * item["quantity"] for item in items)
    return render_template("index.html", page="cart", products=[], cart_items=items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    quantity = request.form.get("quantity", "1")
    try:
        quantity = int(quantity)
    except ValueError:
        quantity = 0
    if quantity < 1:
        flash("Quantity must be at least 1.", "danger")
        return redirect(url_for("home"))
    with get_db() as connection:
        product = connection.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if not product:
            abort(404)
        if product["stock"] < quantity:
            flash("Not enough stock is available.", "danger")
            return redirect(url_for("home"))
        existing = connection.execute(
            "SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
            (session["user_id"], product_id)
        ).fetchone()
        new_quantity = quantity if not existing else existing["quantity"] + quantity
        if new_quantity > product["stock"]:
            flash("Cart quantity cannot exceed available stock.", "danger")
        elif existing:
            connection.execute(
                "UPDATE cart_items SET quantity = ? WHERE id = ?",
                (new_quantity, existing["id"])
            )
            flash("Cart quantity updated.", "success")
        else:
            connection.execute(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                (session["user_id"], product_id, quantity)
            )
            flash("Fruit added to your cart.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/update/<int:cart_item_id>", methods=["POST"])
@login_required
def update_cart(cart_item_id):
    try:
        quantity = int(request.form.get("quantity", "0"))
    except ValueError:
        quantity = 0
    if quantity < 1:
        flash("Quantity must be at least 1.", "danger")
        return redirect(url_for("cart"))
    with get_db() as connection:
        item = connection.execute("""
            SELECT cart_items.id, cart_items.product_id, products.stock
            FROM cart_items
            JOIN products ON products.id = cart_items.product_id
            WHERE cart_items.id = ? AND cart_items.user_id = ?
        """, (cart_item_id, session["user_id"])).fetchone()
        if not item:
            abort(404)
        if quantity > item["stock"]:
            flash("Quantity exceeds available stock.", "danger")
        else:
            connection.execute(
                "UPDATE cart_items SET quantity = ? WHERE id = ?",
                (quantity, cart_item_id)
            )
            flash("Cart updated.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:cart_item_id>", methods=["POST"])
@login_required
def remove_from_cart(cart_item_id):
    with get_db() as connection:
        cursor = connection.execute(
            "DELETE FROM cart_items WHERE id = ? AND user_id = ?",
            (cart_item_id, session["user_id"])
        )
        if cursor.rowcount == 0:
            abort(404)
    flash("Item removed from cart.", "success")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    with get_db() as connection:
        items = connection.execute("""
            SELECT cart_items.quantity, products.id AS product_id,
                   products.name, products.price, products.stock, products.image
            FROM cart_items
            JOIN products ON products.id = cart_items.product_id
            WHERE cart_items.user_id = ?
        """, (session["user_id"],)).fetchall()
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("home"))

    total = sum(item["price"] * item["quantity"] for item in items)
    if request.method == "POST":
        customer_name = request.form.get("customer_name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        payment = request.form.get("payment", "")
        if len(customer_name) < 2 or len(phone) < 8 or len(address) < 10:
            flash("Enter a valid name, phone number and delivery address.", "danger")
        elif payment != "cod":
            flash("Cash on Delivery is the only demo payment option.", "danger")
        else:
            with get_db() as connection:
                current_items = connection.execute("""
                    SELECT cart_items.quantity, products.id AS product_id,
                           products.name, products.price, products.stock
                    FROM cart_items
                    JOIN products ON products.id = cart_items.product_id
                    WHERE cart_items.user_id = ?
                """, (session["user_id"],)).fetchall()
                if not current_items:
                    flash("Your cart is empty.", "warning")
                    return redirect(url_for("home"))
                if any(row["quantity"] > row["stock"] for row in current_items):
                    flash("Stock changed. Please review your cart.", "danger")
                    return redirect(url_for("cart"))

                order_number = datetime.now().strftime("FK-%Y%m%d-%H%M%S-") + secrets.token_hex(3).upper()
                actual_total = sum(row["price"] * row["quantity"] for row in current_items)
                cursor = connection.execute("""
                    INSERT INTO orders
                    (order_number, user_id, customer_name, phone, address, total, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?)
                """, (
                    order_number, session["user_id"], customer_name, phone, address,
                    actual_total, datetime.now().isoformat(timespec="seconds")
                ))
                order_id = cursor.lastrowid
                for row in current_items:
                    connection.execute("""
                        INSERT INTO order_items
                        (order_id, product_id, product_name, price, quantity)
                        VALUES (?, ?, ?, ?, ?)
                    """, (order_id, row["product_id"], row["name"], row["price"], row["quantity"]))
                    connection.execute(
                        "UPDATE products SET stock = stock - ? WHERE id = ?",
                        (row["quantity"], row["product_id"])
                    )
                connection.execute(
                    "DELETE FROM cart_items WHERE user_id = ?", (session["user_id"],)
                )
            flash("Demo COD order placed successfully.", "success")
            return redirect(url_for("order_detail", order_id=order_id))
    return render_template("index.html", page="checkout", products=[], cart_items=items, total=total)


@app.route("/orders")
@login_required
def orders():
    with get_db() as connection:
        orders_list = connection.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],)
        ).fetchall()
    return render_template("index.html", page="orders", products=[], orders_list=orders_list)


@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    with get_db() as connection:
        order = connection.execute(
            "SELECT * FROM orders WHERE id = ? AND user_id = ?",
            (order_id, session["user_id"])
        ).fetchone()
        if not order:
            abort(404)
        order_items = connection.execute(
            "SELECT * FROM order_items WHERE order_id = ?", (order_id,)
        ).fetchall()
    return render_template(
        "index.html", page="order_detail", products=[],
        order=order, order_items=order_items
    )


@app.route("/admin")
@admin_required
def admin():
    with get_db() as connection:
        products = connection.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
        orders_list = connection.execute(
            "SELECT orders.*, users.name AS user_name FROM orders "
            "JOIN users ON users.id = orders.user_id ORDER BY orders.id DESC LIMIT 20"
        ).fetchall()
        stats = {
            "products": connection.execute("SELECT COUNT(*) AS count FROM products").fetchone()["count"],
            "customers": connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'user'"
            ).fetchone()["count"],
            "orders": connection.execute("SELECT COUNT(*) AS count FROM orders").fetchone()["count"],
            "sales": connection.execute(
                "SELECT COALESCE(SUM(total), 0) AS total FROM orders"
            ).fetchone()["total"]
        }
    return render_template(
        "admin.html", products=products, orders_list=orders_list, stats=stats
    )


@app.route("/admin/products/add", methods=["POST"])
@admin_required
def admin_add_product():
    name = request.form.get("name", "").strip()
    price = request.form.get("price", "")
    stock = request.form.get("stock", "")
    image = request.form.get("image", "").strip()
    category = request.form.get("category", "Fresh Fruit").strip()
    description = request.form.get("description", "").strip()
    try:
        price = float(price)
        stock = int(stock)
    except ValueError:
        flash("Price and stock must be valid numbers.", "danger")
        return redirect(url_for("admin"))
    if not name or price < 0 or stock < 0 or not image.startswith(("http://", "https://")):
        flash("Enter a valid name, image URL, price and stock.", "danger")
        return redirect(url_for("admin"))
    with get_db() as connection:
        connection.execute("""
            INSERT INTO products (name, price, image, stock, category, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, price, image, stock, category, description))
    flash("Product added successfully.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/products/edit/<int:product_id>", methods=["POST"])
@admin_required
def admin_edit_product(product_id):
    name = request.form.get("name", "").strip()
    price = request.form.get("price", "")
    stock = request.form.get("stock", "")
    image = request.form.get("image", "").strip()
    category = request.form.get("category", "Fresh Fruit").strip()
    description = request.form.get("description", "").strip()
    try:
        price = float(price)
        stock = int(stock)
    except ValueError:
        flash("Price and stock must be valid numbers.", "danger")
        return redirect(url_for("admin"))
    if not name or price < 0 or stock < 0 or not image.startswith(("http://", "https://")):
        flash("Enter a valid name, image URL, price and stock.", "danger")
        return redirect(url_for("admin"))
    with get_db() as connection:
        cursor = connection.execute("""
            UPDATE products SET name = ?, price = ?, image = ?, stock = ?,
                                category = ?, description = ?
            WHERE id = ?
        """, (name, price, image, stock, category, description, product_id))
        if cursor.rowcount == 0:
            abort(404)
    flash("Product updated successfully.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    with get_db() as connection:
        cursor = connection.execute(
            "DELETE FROM products WHERE id = ?", (product_id,)
        )
        if cursor.rowcount == 0:
            abort(404)
    flash("Product deleted successfully.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@admin_required
def admin_update_order_status(order_id):
    status = request.form.get("status", "")
    allowed = {"Pending", "Confirmed", "Delivered", "Cancelled"}
    if status not in allowed:
        flash("Invalid order status.", "danger")
        return redirect(url_for("admin"))
    with get_db() as connection:
        cursor = connection.execute(
            "UPDATE orders SET status = ? WHERE id = ?", (status, order_id)
        )
        if cursor.rowcount == 0:
            abort(404)
    flash("Order status updated.", "success")
    return redirect(url_for("admin"))


@app.route("/api/fruits")
def api_fruits():
    from flask import jsonify
    with get_db() as connection:
        rows = connection.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(row) for row in rows])


@app.errorhandler(403)
def forbidden(error):
    return render_template("index.html", page="error",
                           products=[], error_code=403,
                           error_message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("index.html", page="error",
                           products=[], error_code=404,
                           error_message="The page you requested was not found."), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("index.html", page="error",
                           products=[], error_code=400,
                           error_message=str(error.description)), 400


if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")
