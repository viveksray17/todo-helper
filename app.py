from flask import Flask, render_template, redirect, url_for, request
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "1234"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    todos = db.relationship('Todo', backref='author', lazy=True)

    def __repr__(self) -> str:
        return f"User('{self.username}')"


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow)
    desc = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Todo('{self.title}', '{self.date_posted}')"


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password',
                             validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired()], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password',
                             validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Log In')


@app.route("/", methods=["GET", "POST"])
def home():
    if current_user.is_authenticated:
        user = current_user  # This is very important info to be NOTED
        if request.method == "POST":
            todo_title = request.form["todo_title"]
            todo_desc = request.form["todo_desc"]
            user_id = user.id
            todo = Todo(title=todo_title, desc=todo_desc, user_id=user_id)
            db.session.add(todo)
            db.session.commit()
            flash(f"Todo Added Successfully", "success")
            return redirect(url_for('home'))
        user_todos = user.todos
        return render_template("dashboard.html", title="DashBoard", user=user, todos=user_todos)

    else:
        return render_template("home.html", title="Home")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()  # form is an instance of LoginForm
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash(f"{form.username.data} Logged In!", "success")
                return redirect(url_for("home"))
    return render_template("login.html", title="Login", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if User.query.filter_by(username=form.username.data).first():
        flash(
            f"Username {form.username.data} already exists. Please choose a different one!", "danger")
        return redirect(url_for("register"))

    if form.password.data != form.confirm_password.data:
        flash(f"Passwords do not Match", "danger")
        return redirect(url_for("register"))

    elif form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user_created = User(username=form.username.data,
                            password=hashed_password)
        db.session.add(user_created)
        db.session.commit()
        flash(f"Account created for {form.username.data}!", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Register", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/delete/<int:id>")
def delete(id):
    todo = Todo.query.filter_by(id=id).first()
    db.session.delete(todo)
    db.session.commit()
    flash(f"Todo Deleted Successfully", "success")
    return redirect(url_for("home"))


@app.route("/update/<int:id>", methods=["GET", "POST"])
def update(id):
    if request.method == "POST":
        todo_title = request.form["todo_title"]
        todo_desc = request.form["todo_desc"]
        todo = Todo.query.filter_by(id=id).first()
        todo.title = todo_title
        todo.desc = todo_desc
        db.session.add(todo)
        db.session.commit()
        flash(f"Todo Updated Successfully", "success")
        return redirect(url_for("home"))
    todo = Todo.query.filter_by(id=id).first()
    return render_template("update.html", title="Update", todo=todo)


if __name__ == "__main__":
    app.run(debug=True)
