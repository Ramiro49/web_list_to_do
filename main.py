from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SelectField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from time import sleep
import threading
import smtplib

# Email from where the notification will be sent
my_email = ""
my_password = ""

app = Flask(__name__)
app.config["SECRET_KEY"] = "a9l8ñsSD7jd4GE564Gf34"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
Bootstrap(app)

# Create DataBase
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///web_task_list.db"
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def check_deadlines():
    while True:
        tasks_color_success = TaskToDo.query.filter_by(color="success")
        tasks_color_warning = TaskToDo.query.filter_by(color="warning")

        # Sort the task lists
        tasks_color_success = sorted(task.date_time for task in tasks_color_success)
        tasks_color_warning = sorted(task.date_time for task in tasks_color_warning)

        for date_time in tasks_color_success:
            # If there are 15 minutes until the deadline
            if datetime.now() + timedelta(minutes=15) >= date_time:
                # For every task with the deadline "date_time" change the color from "success" to "warning" (Bootstrap)
                tasks_to_color_warning = TaskToDo.query.filter_by(date_time=date_time)
                for task in tasks_to_color_warning:
                    task.color = "warning"
                    db.session.commit()
                    # If user is active reload page because color has changed
                    if task.user.is_active:
                        # SOME CODE HERE TO RELOAD THE PAGE
                        print("user_active: reload page")
            # If the task deadline left more than 15 minutes
            else:
                # Break the for loop, because the list is sorted and the rest of the tasks in the
                # list will have a due date of more than 15 minutes.
                break

        for date_time in tasks_color_warning:
            # If there are 1 minute until the deadline
            if datetime.now() + timedelta(minutes=1) >= date_time:
                # For every task with the deadline "date_time" change the color from "success" to "warning" (Bootstrap)
                tasks_to_color_danger = TaskToDo.query.filter_by(date_time=date_time)
                for task in tasks_to_color_danger:
                    task.color = "danger"
                    db.session.commit()
                    if task.email_notification:
                        send_email(task)
                    if task.user.is_active:
                        # SOME CODE HERE TO RELOAD THE PAGE
                        print("user_active: reload page")
            else:
                break
        sleep(15)


def send_email(task):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=my_password)

        connection.sendmail(
            from_addr=my_email,
            to_addrs=task.user.email,
            msg=f'Subject:{task.task_name}, {task.date_time}\n\n'
                f'Hi! {task.user.username}, remember to {task.task_name} at {task.date_time}'
        )


# Table Data Base
# -------------------------------------------------------------------------------------------------------------------- #
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(15), unique=True, nullable=False)
    email = Column(String(30), unique=True, nullable=False)
    password = Column(String(100), nullable=False)

    tasks = relationship("TaskToDo", back_populates="user")


class TaskToDo(db.Model):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="tasks")

    task_name = Column(String(50), nullable=False)
    date_time = Column(DateTime(timezone=False), nullable=False)
    email_notification = Column(Boolean, nullable=False)
    color = Column(String(15), nullable=False)


# db.create_all()
# -------------------------------------------------------------------------------------------------------------------- #


# Flask forms
# -------------------------------------------------------------------------------------------------------------------- #
class LoginForm(FlaskForm):
    email = EmailField("Email",
                       validators=[DataRequired(), Email(), Length(max=30)],
                       render_kw={"placeholder": "Write your email address"})
    password = PasswordField("Password",
                             validators=[DataRequired(), Length(min=8, max=25)],
                             render_kw={"placeholder": "Write your password"})
    submit = SubmitField("Go!")


class CreateAccount(FlaskForm):
    username = StringField(validators=[DataRequired(), Length(min=3, max=15)],
                           render_kw={"placeholder": "Write your username"})
    email = EmailField(validators=[DataRequired(), Email(), Length(max=30)],
                       render_kw={"placeholder": "Write your email address"})
    password = PasswordField(validators=[DataRequired(), Length(min=8, max=25)],
                             render_kw={"placeholder": "Write your password"})
    confirm_password = PasswordField(validators=[DataRequired(),
                                                 EqualTo("password", message="Passwords must match")],
                                     render_kw={"placeholder": "Repeat your password"})
    submit = SubmitField("Create")


class CreateItemList(FlaskForm):
    task = StringField(validators=[DataRequired(), Length(max=50)],
                       render_kw={"placeholder": "Write your task here..."})
    day = IntegerField(validators=[DataRequired(message="This field is required as a number.")],
                       render_kw={"placeholder": "DD"})
    month = SelectField(choices=['January', 'February', 'March', 'April', 'May', 'June', 'July',
                                 'August', 'September', 'October', 'November', 'December'])
    year = IntegerField(validators=[DataRequired(message="This field is required as a number.")],
                        render_kw={"placeholder": "YYYY"})
    hour = SelectField(choices=[f"{num:02d}" for num in range(24)])
    minute = SelectField(choices=[f"{num:02d}" for num in range(61)])
    email_notification = BooleanField("Send me an email notification")
    submit = SubmitField("Save")
# -------------------------------------------------------------------------------------------------------------------- #


# Routes
# -------------------------------------------------------------------------------------------------------------------- #
@app.route("/", methods=["GET", "POST"])
def home():
    year = datetime.now().year
    form = CreateItemList()
    task_list = []
    error_list = list()

    if form.validate_on_submit():
        date_time_str = f"{form.day.data}/{form.month.data}/{form.year.data} {form.hour.data}:{form.minute.data}"
        try:
            date_time_obj = datetime.strptime(date_time_str, "%d/%B/%Y %H:%M")
        except ValueError:
            error_list.append(('date', ["Please write an existing date."]))
        else:
            if date_time_obj > datetime.now():
                new_task = TaskToDo(task_name=form.task.data,
                                    date_time=date_time_obj,
                                    email_notification=form.email_notification.data,
                                    color="success",
                                    user=current_user)
                db.session.add(new_task)
                db.session.commit()
                return redirect(url_for("home"))
            else:
                error_list.append(('date', ["Please write a future date."]))

    error_list.extend(list(form.errors.items()))

    if current_user.is_authenticated:
        task_list = current_user.tasks
    else:
        error_list = [('account', ["You need to create an account."])]

    return render_template("index.html.j2", form=form, task_list=task_list,
                           error_list=error_list, user=current_user, year=year)


@app.route("/create_account", methods=["GET", "POST"])
def create_account():
    year = datetime.now().year
    form = CreateAccount()
    error_list = list()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data

        if User.query.filter_by(username=username).first():
            error_list.append(('username', [f"The username {username} is already taken."]))

        if User.query.filter_by(email=email).first():
            error_list.append(('email', [f"The email {email} is already registered"]))

        # If there are no errors, create account
        if not len(error_list):
            hash_and_salted_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)

            new_user = User(username=username, email=email, password=hash_and_salted_password)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("home"))

    error_list.extend(list(form.errors.items()))

    return render_template("create_account.html.j2", form=form, error_list=error_list, user=current_user, year=year)


@app.route("/login", methods=["GET", "POST"])
def login():
    year = datetime.now().year
    form = LoginForm()
    error = []

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # if user exist and the password is correct, then login
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("home"))
            else:
                error.append(["password", "Password incorrect, please try again."])
        else:
            error.append(["email", "That email does not exist, please try again."])

    return render_template("login.html.j2", form=form, error=error, user=current_user, year=year)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/delete_task/<int:task_id>")
def delete_task(task_id):
    task_to_delete = TaskToDo.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for("home"))
# -------------------------------------------------------------------------------------------------------------------- #


t = threading.Thread(target=check_deadlines)
t.setDaemon(True)
t.start()

if __name__ == '__main__':
    app.run()
