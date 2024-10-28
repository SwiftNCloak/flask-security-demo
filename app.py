from flask import Flask, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))  # Storing plaintext password

@app.route('/')
def index():
    return render_template('index.html')

# Vulnerable Version
@app.route('/register', methods=['GET', 'POST'])
def register_vulnerable():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Vulnerable Version:
        # This version does NOT hash the password and is insecure.
        # Storing plaintext passwords directly is a major security risk.
        vulnerable_user = User(username=username, password=password)  # Storing plaintext password
        db.session.add(vulnerable_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully (vulnerable)!"})

    return render_template('register.html', version='vulnerable')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
