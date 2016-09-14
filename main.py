import os
import re
import webapp2
import jinja2
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# Encryption Key Word
SECRET = "HELLOWORLD"

# Constants
LOGOUT = "LOGOUT"
LOGIN = "LOGIN"
KEYNAME = "udacity"

# Database Classes
class Blog(db.Model):
    name = db.StringProperty(required = True)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    likes = db.IntegerProperty(default = 0)
    dislikes = db.IntegerProperty(default = 0)
    created = db.DateTimeProperty(auto_now_add = True)

    like_userlist = db.StringListProperty(default = None)
    dislike_userlist = db.StringListProperty(default = None)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

class Comment(db.Model):
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    edit_auth = db.BooleanProperty(default = False)
    edit_enable = db.BooleanProperty(default = False)
    created = db.DateTimeProperty(auto_now_add = True)

# Encryption Related Functions
class Encryption():
    def hash_str(self, s):
        return hmac.new(SECRET,s).hexdigest()

    def make_secure_val(self, s):
        return "%s|%s" % (s, self.hash_str(s))

    def check_secure_val(self, h):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val

    def make_salt(self):
        return ''.join(random.choice(string.letters) for i in range(5))

    def make_pw_hash(self, name, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        return "%s,%s" % (hashlib.sha256(name+pw+salt).hexdigest(), salt)

    def valid_pw(self, name, pw, h):
        value = h.split(',')
        return h == self.make_pw_hash(name, pw, value[1])

# User Input Parsing and Verification
class InputVerification():
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_password(self, password):
        return self.PASS_RE.match(password)

    def valid_email(self, email):
        return self.EMAIL_RE.match(email)

# Common Handler Functions
class Handler(webapp2.RequestHandler, Encryption, InputVerification):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def getUser_Logged(self):
        username_str = self.request.cookies.get('username')
        if username_str:
            username_val = self.check_secure_val(username_str)
            if username_val:
                blog = Blog.get_or_insert(KEYNAME, name = "Udacity")
                user_key = db.Key.from_path('User', str(username_val), parent = blog.key())
                user = db.get(user_key)
                if user:
                    return user
        return None

    def getUser(self, username=""):
        if username:
            blog = Blog.get_or_insert(KEYNAME, name = "Udacity")
            user_key = db.Key.from_path('User', str(username), parent = blog.key())
            user = db.get(user_key)
            if user:
                return user
        return None

    def initCommentEditAuth(self):
        user = self.getUser_Logged()
        if user:
            comments = Comment.all()
            comments.filter("author =", user.username)
            for comment in comments:
                comment.edit_auth = True
                comment.put()

    def resetCommentEditAuth(self):
        comments = db.GqlQuery("SELECT * FROM Comment WHERE edit_auth = True")
        for comment in comments:
            comment.edit_auth = False
            comment.put()

#resets all Comment Edit Enable Properties except for specified comment_id
    def resetCommentEditEnable(self, comment_id=""):
        comments = db.GqlQuery("SELECT * FROM Comment WHERE edit_enable = True")
        if not comment_id:
            for comment in comments:
                comment.edit_enable = False
                comment.put()
        else:
            for comment in comments:
                if not str(comment.key().id()) == comment_id:
                    comment.edit_enable = False
                    comment.put()

"""
*
* Main Content Handlers
*
"""
# Main Page Handler
class MainHandler(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        if self.getUser_Logged():
            self.render("home.html", log_text = LOGOUT, posts = posts)
        else:
            self.render("home.html", log_text = LOGIN, posts = posts)

# Login Page Handler
class LoginHandler(Handler):
    def get(self):
        #Handles user logout or login
        user = self.getUser_Logged()
        if user:
            self.resetCommentEditAuth()
            self.response.headers.add_header('Set-Cookie','username=; Path=/')
            self.redirect("/")
        else:
            self.render("login.html", log_text = LOGIN)

    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')

        if self.valid_username(username) and self.valid_password(password):
            blog = Blog.get_by_key_name(KEYNAME)
            user_key = db.Key.from_path('User', str(username), parent = blog.key())
            user = db.get(user_key)
            if user and self.valid_pw(username, password, user.password):
                username_hash = self.make_secure_val(username)
                self.response.headers.add_header('Set-Cookie','username=%s; Path=/' % str(username_hash))
                self.redirect('/welcome')
                return

        params = {"error": "Invalid Username and/or Password", "username" : username, "log_text": LOGIN}
        self.render("login.html", **params)

#Signup Page Handler
class SignupHandler(Handler):
    def get(self):
        self.render("signup.html", log_text = LOGIN)

    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')
        verify = self.request.get('input_verify')
        email = self.request.get('input_email')

        params = {"error_username" : "", "error_password": "", "error_verify": "", "error_email":"", "username" : username,"email": email, "log_text" : "LOGIN"}

        input_valid = True
        if not self.valid_username(username):
            params["error_username"] = "That's not a valid username.<br>"
            input_valid = False
        elif self.getUser(username):
            params["error_username"] = "This username has been taken."
            input_valid = False

        if not self.valid_password(password):
            params["error_password"] = "That wasn't a valid password.<br>"
            input_valid = False
        if not password == verify:
            params["error_verify"] = "Your passwords didn't not match.<br>"
            input_valid = False
        if not self.valid_email(email):
            params["error_email"] = "That's not a valid email.<br>"
            input_valid = False

        if input_valid:
            password_encrypt = self.make_pw_hash(name = username, pw = password)
            blog = Blog.get_or_insert(KEYNAME, name = "Udacity")
            new_user = User(parent = blog, key_name=username, username=username, password = password_encrypt, email=email)
            new_user.put()
            self.redirect('/login')
        else:
            self.render('signup.html', **params)

# New Post Handler
class NewPostHandler(Handler):
    def get(self):
        if self.getUser_Logged():
            self.render("newpost.html", log_text=LOGOUT)
        else:
            self.render("newpost.html", log_text=LOGIN)

    def post(self):
        params = {"error" : "", "subject" : "", "content": "", "log_text" : ""}

        user = self.getUser_Logged()
        if not user:
            params["error"] = "You're not logged in! Please login before you post."
            params["log_text"] = "LOGIN"
        else:
            subject = self.request.get("subject")
            content = self.request.get("content")

            if not subject and  not content:
                params["error"] = "You're missing a subject and the content"
            elif not subject:
                params["error"] = "You're missing a subject!"
            elif not content:
                params["error"] = "You're missing the content!"

            if not params["error"]:
                blog = Blog.get_or_insert(KEYNAME, name = "Udacity")
                post = Post(parent=blog, subject=subject, author=user.username, content=content)
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
                return

        self.render("newpost.html", **params)

#Post Handler
class PostHandler(Handler):
    def get(self, post_id, comment_id=""):
        blog = Blog.get_by_key_name(KEYNAME)
        p_key = db.Key.from_path('Post', int(post_id), parent = blog.key())
        post = db.get(p_key)

        self.resetCommentEditEnable(comment_id)
        self.initCommentEditAuth()

        if not post:
            self.error(404)
            return

        comments = db.GqlQuery("SELECT * FROM Comment WHERE ANCESTOR IS :1 ", post)

        params = {"log_text" : "", "post" : post, "like_enable" : False, "dislike_enable" : False, "comment_enable" : False, "comments" : comments, "edit_enable" : False}

        user = self.getUser_Logged()
        if user:
            params["log_text"] = LOGOUT
            params["comment_enable"] = True
            if not user.username == post.author:
                params["like_enable"] = True
                params["dislike_enable"] = True
            else:
                params["edit_enable"] = True
        else:
            params["log_text"] = LOGIN

        self.render("post.html", **params)

    def post(self, post_id, edit = ""):
        blog = Blog.get_by_key_name(KEYNAME)
        p_key = db.Key.from_path('Post', int(post_id), parent = blog.key())
        post = db.get(p_key)

        if not post:
            self.error(404)
            return

        button_value = (self.request.get("input_button")).split(',')
        user = self.getUser_Logged()
        comment_id = ""

        if button_value[0] == "like":
            if user.username in post.dislike_userlist:
                post.dislikes -= 1
                post.dislike_userlist.remove(user.username)
            if not user.username in post.like_userlist:
                post.likes += 1
                post.like_userlist.append(user.username)
            post.put()
        elif button_value[0] == "dislike":
            if user.username in post.like_userlist:
                post.likes -= 1
                post.like_userlist.remove(user.username)
            if not user.username in post.dislike_userlist:
                post.dislikes += 1
                post.dislike_userlist.append(user.username)
            post.put()
        elif button_value[0] == "comment":
            new_content = self.request.get("comment_text","")
            new_comment = Comment(parent=post, author=user.username, content=new_content, edit_auth= True)
            new_comment.put()
        elif button_value[0] == "edit":
            self.redirect('/edit/%s' % str(post.key().id()))
            return
        elif button_value[0] == "delete":
            comments = db.GqlQuery("SELECT * FROM Comment WHERE ANCESTOR IS :1 ", post)
            for comment in comments:
                comment.delete()
            post.delete()
            self.redirect('/')
            return
        elif button_value[0] == "editcomment":
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent = post.key())
            comment = db.get(c_key)
            comment.edit_enable = True
            comment_id = str(comment.key().id())
            comment.put()
        elif button_value[0] == "deletecomment":
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent = post.key())
            comment = db.get(c_key)
            comment.delete()
        elif button_value[0] == "submitcomment":
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent = post.key())
            comment = db.get(c_key)
            comment.content = self.request.get("textarea-" + button_value[1])
            comment.edit_enable = False
            comment.put()

        if comment_id:
            self.redirect('/post/%s/%s' % (str(post.key().id()), comment_id))
        else:
            self.redirect('/post/%s' % str(post.key().id()))

class EditHandler(Handler):
    def get(self, post_id):
        blog = Blog.get_by_key_name(KEYNAME)
        p_key = db.Key.from_path('Post', int(post_id), parent = blog.key())
        post = db.get(p_key)

        params = {"subject" : post.subject, "content" : post.content}
        self.render('edit.html', **params)

    def post(self, post_id):
        button_value = self.request.get("input_button")

        if button_value == "submit":
            subject = self.request.get("subject")
            content = self.request.get("content")

            params = {"error" : "", "subject" : subject, "content": content, "log_text" : "LOGOUT"}

            if not subject and  not content:
                params["error"] = "You're missing a subject and the content"
            elif not subject:
                params["error"] = "You're missing a subject!"
            elif not content:
                params["error"] = "You're missing the content!"

            if params["error"]:
                self.render('newpost.html', **params)
            else:
                blog = Blog.get_by_key_name(KEYNAME)
                key = db.Key.from_path('Post', int(post_id), parent = blog.key())
                post = db.get(key)
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
        elif button_value == "cancel":
            self.redirect('/post/%s' % post_id)

class WelcomeHandler(Handler):
    def get(self):
        user = self.getUser_Logged()
        self.render("welcome.html", username = user.username, log_text = LOGOUT)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/home', MainHandler),
    ('/login',LoginHandler),
    ('/signup', SignupHandler),
    ('/newpost', NewPostHandler),
    ('/post/([0-9]+)', PostHandler),
    ('/edit/([0-9]+)', EditHandler),
    ('/post/([0-9]+)/([0-9]+)', PostHandler),
    ('/welcome', WelcomeHandler)
], debug=True)