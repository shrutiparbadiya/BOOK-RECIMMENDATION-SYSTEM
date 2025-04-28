from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
import re
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from collections import OrderedDict
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = "your_secret_key"

db_path = "users.db"
file_path = "DATA/dept_books.csv"

# Initialize database
def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS wishlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    book_name TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()
init_db()
# Load dataset
df = pd.read_csv(file_path)
df.dropna(subset=["Book Name", "Subject", "image_url"], inplace=True)
df.drop_duplicates(subset=["Book Name"], inplace=True)

def sort_subjects(books_by_subject):
    sorted_subjects = OrderedDict()
    for subject in sorted(books_by_subject.keys()):
        if subject != "Other":
            sorted_subjects[subject] = books_by_subject[subject]
    if "Other" in books_by_subject:
        sorted_subjects["Other"] = books_by_subject["Other"]
    return sorted_subjects


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    books_by_subject = {}
    seen_books = set()

    for _, row in df.iterrows():
        subject = row["Subject"]
        book_name = row["Book Name"]
        image_url = row["image_url"]
        if book_name not in seen_books:
            seen_books.add(book_name)
        if subject not in books_by_subject:
            books_by_subject[subject] = []
        books_by_subject[subject].append((book_name, image_url))

    books_by_subject = sort_subjects(books_by_subject)
    return render_template('homepage.html', username=session['username'], books_by_subject=books_by_subject)

from urllib.parse import unquote

@app.route('/book/<book_name>')
def book_details(book_name):
    book_name = unquote(book_name)  # Decode URL-encoded book names like %20, %26, etc.
    
    book = df[df["Book Name"].str.strip().str.lower() == book_name.strip().lower()]
    
    if book.empty:
        return "Book not found", 404

    book = book.iloc[0]
    subject = book["Subject"]

    recommendations = df[(df["Subject"] == subject) & (df["Book Name"] != book_name)][["Book Name", "image_url"]]
    recommendations_list = recommendations.sample(n=min(5, len(recommendations)), replace=False).values.tolist()

    # Wishlist check (if session user exists)
    is_in_wishlist = False
    if 'username' in session:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM wishlist WHERE username = ? AND book_name = ?", (session['username'], book_name))
        is_in_wishlist = c.fetchone() is not None
        conn.close()
    
    username=session['username']
    return render_template(
        'book_details.html',
        book_name=book_name,
        author=book["Name of Authors"],
        image_url=book["image_url"],
        recommendations=recommendations_list,
        is_in_wishlist=is_in_wishlist,
	username=username
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match")

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return render_template('signup.html', error="Username already exists")

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/add_to_wishlist/<book_name>', methods=['POST'])
def add_to_wishlist(book_name):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    username = session['username']

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM wishlist WHERE username = ? AND book_name = ?", (username, book_name))
    if not c.fetchone():
        c.execute("INSERT INTO wishlist (username, book_name) VALUES (?, ?)", (username, book_name))
        conn.commit()
    conn.close()

    return jsonify({'status': 'success'})

    

@app.route('/wishlist')
@app.route('/wishlist')
def wishlist():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT book_name FROM wishlist WHERE username = ?", (username,))
    books = [row[0] for row in c.fetchall()]
    conn.close()

    # Group wishlist books by subject
    wishlist_by_subject = {}
    for book in books:
        book_data = df[df["Book Name"] == book]
        if not book_data.empty:
            subject = book_data["Subject"].values[0]
            image_url = book_data["image_url"].values[0]
            if subject not in wishlist_by_subject:
                wishlist_by_subject[subject] = []
            wishlist_by_subject[subject].append((book, image_url))

    wishlist_by_subject = sort_subjects(wishlist_by_subject)

    return render_template("wishlist.html", wishlist_by_subject=wishlist_by_subject, username=username)

@app.route('/remove_from_wishlist/<book_name>', methods=['POST'])
def remove_from_wishlist(book_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("DELETE FROM wishlist WHERE username = ? AND book_name = ?", (username, book_name))
    conn.commit()
    conn.close()

    return redirect(url_for('wishlist'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', username=session['username'])


if __name__ == '__main__':
    app.run(debug=True)



#wishlist_books = []
    #if 'wishlist' in session:
     #  	wishlist_books = [
	#(book, df[df["Book Name"] == book]["image_url"].values[0])
       	#for book in session['wishlist']
   	#if not df[df["Book Name"] == book].empty
      	#]

    #return render_template(
     #   'homepage.html',
      #  username=session['username'],
       # books_by_subject=books_by_subject,
        #wishlist=wishlist_books
    #)
