from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from datetime import datetime
from functools import wraps
import requests
import os

# : Flask-login module is use to do access control.It provides user session management for Flask: logging in,
# logging out, and remembering session. The module stores the user ID, restricts views to logged in users,
# protects cookies and has many other features. Install the extension with pip----$ pip install flask-login.


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

url = "https://quotes15.p.rapidapi.com/quotes/random/"
headers = {
    "X-RapidAPI-Key": "569965a1camsh50a4befb9eed944p10cc0cjsnb2b575fe1174",
    "X-RapidAPI-Host": "quotes15.p.rapidapi.com",
}


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # : #This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()

## : Configuring application for flask-login extension.
#: The most important part of an application that uses Flask-Login is the LoginManager class. it is created as follow:
login_manager = LoginManager()
###: The login manager contains the code that lets your application and Flask-Login work together, such as how to load
# a user from an ID, where to send users when they need to log in, and the like.Once the actual application object has
# been created, you can configure it for login with:
login_manager.init_app(app)


def api():
    response = requests.get(url, headers=headers)
    data = response.json()
    return data


# That user_id will come from the user session. If they're logged in, they will have it set as their identity.
# When a request comes in, user loader attempts to load a user object using this identity and check whether the user
# exists and is active (not blocked). If all goes well the user is considered authenticated and the object user loader
# returns can be accessed across the app (within request context) as current_user.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# : Creating admin-only decorator.
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #: if user id != 1 and not current_user.is_authenticated the return abort with 403 error.
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # otherwise continue with the route function.
        return f(*args, **kwargs)

    return decorated_function


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


@app.route('/')
def get_all_posts():
    quote = api()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, quote=quote, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    #: form.validate_on_submit() This rule says 'if the request method is POST and
    # if the form field(s) are valid, then proceed.
    if form.validate_on_submit():
        #: Then do the following.
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, please log in instead!")
            return redirect(url_for('login'))
        # : 1st Hashing and salting the plain text password inputted by the user and save it as a variable.
        harsh_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        # : note-Password-Based Key Derivation Function 2 (PBKDF2) algorithm that uses a Hashed Message Authentication
        # Code (HMAC) based on the SHA256 (Secure Hash Algorithm 256) message digest algorithm as the underlying
        # pseudorandom function.
        # : 2nd Getting hold of the data entered by the user and store it as a variable.
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=harsh_and_salted_password,
        )
        #: 3rd adding the data in the new_user variable to the database.
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login.
        login_user(new_user)
        #: 4th logging in the user and redirecting to the home page by passing get_all_posts function.
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    #: creating form object from LoginForm class and then passing the form object to template(login.html).
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email does not exist, please try again!")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect,please try again!")
            return redirect(url_for('login'))
        else:
            login_user(user)
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    return render_template("contact.html", message_sent=False)


@app.route("/new-post", methods=["GET", "POST"])
# : mark with admin-only decorator.
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, host='localhost', port=5000)
