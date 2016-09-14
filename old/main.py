import os
import re

import webapp2
import jinja2

import hashlib
import hmac

import random
import string

import itertools

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = "HELLOWORLD"

def blog_key(name = 'default'):
    return db.Key.from_path('Post', name)

def comment_key(name = 'default'):
    return db.Key.from_path('Comment', name)

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

class Handler(webapp2.RequestHandler, Encryption, InputVerification):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def isUser_Logged(self):
        username_str = self.request.cookies.get('username')
        if username_str:
            username_val = self.check_secure_val(username_str)
            if username_val:
                user_key = db.Key.from_path('User', str(username_val))
                user = db.get(user_key)
                if user:
                    return user
        return None

    def isUser(self, username=""):
        if username:
            user_key = db.Key.from_path('User', str(username))
            user = db.get(user_key)
            if user:
                return user
        return None

    def adjustCommentEdit(self, enable, username =""):
        if not username:
            user = isUser_Logged
            if user:
                comments = Comment.all()
                comments.filter("author =", user.username)
                for comment in comments:
                    comment.edit_enable = enable
                    comment.put()
        else:
            comments = Comment.all()
            comments.filter("author =", username)
            for comment in comments:
                comment.edit_enable = enable
                comment.put()
    def set_editcomment(self, target):
        comments = db.GqlQuery("SELECT * FROM Comment WHERE edit_mode = True")
        for comment in comments:
            comment.edit_mode = False
            comment.put()
        target.edit_mode = True
        target.put()

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    likes = db.IntegerProperty(required = True)
    dislikes = db.IntegerProperty(required = True)
    postkey = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)

    like_list= db.StringListProperty(required = True)
    dislike_list = db.StringListProperty(required = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

class Comment(db.Model):
    author = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    postkey = db.StringProperty(required = True)
    edit_mode = db.BooleanProperty(required = True, default = False)
    edit_enable = db.BooleanProperty(required = True, default = False)
    commentkey = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

class MainHandler(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        if self.isUser_Logged():
            self.render("home.html", log_text="LOGOUT", posts=posts)
        else:
            self.render("home.html", log_text="LOGIN", posts=posts)


class LoginHandler(Handler):
    def get(self):
        user = self.isUser_Logged()
        if user:
            self.adjustCommentEdit(enable = False, username = user.username)
            self.response.headers.add_header('Set-Cookie','username=; Path=/')
            self.redirect("/")
        else:
            self.render("login.html", log_text = "LOGIN")

    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')

        params = {"error" : "", "username" : "", "log_text" : "LOGIN"}

        valid_input = True
        if not self.valid_username(username):
            valid_input = False
        if not self.valid_password(password):
            valid_input = False

        if valid_input:
            user_key = db.Key.from_path('User', str(username))
            user = db.get(user_key)
            if user and self.valid_pw(username, password, user.password):
                self.adjustCommentEdit(True, user.username)
                username_hash = self.make_secure_val(username)
                self.response.headers.add_header('Set-Cookie','username=%s; Path=/' % str(username_hash))
                self.redirect('/welcome')
                return

        params["error"] = "Invalid Username and/or Password"
        self.render("login.html", **params)

class SignupHandler(Handler):
    def get(self):
        self.render("signup.html", log_text = "LOGIN")
    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')
        verify = self.request.get('input_verify')
        email = self.request.get('input_email')

        params = {"error_username" : "", "error_password": "", "error_verify": "", "error_email":"", "username" : username,"email": email, "log_text" : "LOGIN"}

        signupsucess = True
        if not self.valid_username(username):
            params["error_username"] = "That's not a valid username.<br>"
            signupsucess = False
        elif self.isUser(username):
            params["error_username"] = "This username has been taken."
            signupsucess = False

        if not self.valid_password(password):
            params["error_password"] = "That wasn't a valid password.<br>"
            signupsucess = False
        if not password == verify:
            params["error_verify"] = "Your passwords didn't not match.<br>"
            signupsucess = False
        if not self.valid_email(email):
            params["error_email"] = "That's not a valid email.<br>"
            signupsucess = False

        if signupsucess:
            encrypt_password = self.make_pw_hash(name=username, pw=password)
            new_user = User(key_name=username, username=username, password=encrypt_password, email=email)
            new_user.put()
            self.redirect('/login')
        else:
            self.render('signup.html', **params)

class NewPostHandler(Handler):
    def get(self):
        if self.isUser_Logged():
            self.render("newpost.html", log_text="LOGOUT")
        else:
            self.render("newpost.html", log_text="LOGIN")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        params = {"error" : "", "subject" : subject, "content": content, "log_text" : "LOGOUT"}

        if not subject and  not content:
            params["error"] = "You're missing a subject and the content"
        elif not subject:
            params["error"] = "You're missing a subject!"
        elif not content:
            params["error"] = "You're missing the content!"

        user = self.isUser_Logged()
        if not user:
            params["error"] = "You're not logged in! Please login before you post."
            params["log_text"] = "LOGIN"

        if params["error"]:
            self.render('newpost.html', **params)
        else:
            new_key = blog_key()
            post = Post(parent=new_key, subject=subject, content=content, likes=0, dislikes=0, author=user.username, like_list=[], dislike_list=[])
            post.put()
            self.redirect('/post/%s' % str(post.key().id()))

class PostHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all()
        if comments:
            comments.filter("postkey =", post_id)

        params = {"log_text" : "", "post" : post, "like_enable" : False, "dislike_enable" : False, "comment_enable" : False, "comments" : comments, "edit_enable" : False}

        user = self.isUser_Logged()
        if user:
            params["log_text"]="LOGOUT"
            params["comment_enable"] = True
            if not user.username == post.author:
                params["like_enable"] = True
                params["dislike_enable"] = True
            else:
                params["edit_enable"] = True
        else:
            params["log_text"]="LOGIN"

        self.render('post.html', **params)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        user = self.isUser_Logged()
        button_value = (self.request.get("input_button")).split(',')
        comment_content = self.request.get("comment_text","")

        if button_value[0] == "like" :
            if user.username in post.dislike_list:
                post.dislikes -= 1
                post.dislike_list.remove(user.username)
            if not user.username in post.like_list:
                post.likes += 1
                post.like_list.append(user.username)
            post.put()
        elif button_value[0] == "dislike":
            if user.username in post.like_list:
                post.likes -= 1
                post.like_list.remove(user.username)
            if not user.username in post.dislike_list:
                post.dislikes += 1
                post.dislike_list.append(user.username)
            post.put()
        elif button_value[0] == "comment":
            c_key = comment_key()
            c = Comment(parent=c_key, author=user.username, comment=comment_content, postkey=post_id, edit_enable = True)
            c.put()
        elif button_value[0] == "edit":
            self.redirect('/edit/%s' % str(post.key().id()))
            return
        elif button_value[0] == "delete":
            comments = Comment.all()
            comments.filter("postkey =", post_id)
            for comment in comments:
                comment.delete()
            post.delete()
            self.redirect('/')
            return
        elif button_value[0] == "deletecomment":
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent=comment_key())
            comment = db.get(c_key)
            comment.delete()
        elif button_value[0] == "editcomment":
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent=comment_key())
            comment = db.get(c_key)
            self.set_editcomment(comment)
        elif button_value[0] == "submitcomment":
            uiTextName = "textarea-"+button_value[1]
            new_content = self.request.get(uiTextName)
            c_key = db.Key.from_path('Comment', int(button_value[1]), parent=comment_key())
            target_comment = db.get(c_key)
            if target_comment:
                target_comment.comment = new_content
                target_comment.put()
        self.redirect('/post/%s' % str(post.key().id()))

class EditHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

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
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
        elif button_value == "cancel":
            self.redirect('/post/%s' % post_id)


class WelcomeHandler(Handler):
    def get(self):
        user = self.isUser_Logged()
        self.render('welcome.html', username = user.username, log_text="LOGOUT")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/home', MainHandler),
    ('/login',LoginHandler),
    ('/signup', SignupHandler),
    ('/newpost', NewPostHandler),
    ('/post/([0-9]+)', PostHandler),
    ('/edit/([0-9]+)', EditHandler),
    #('/post/([0-9]+)/([0-9+)', CommentHandler)
    ('/welcome', WelcomeHandler)
], debug=True)