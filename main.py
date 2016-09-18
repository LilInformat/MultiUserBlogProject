import os
import webapp2
import jinja2

from common import Const
from datamodels import db, Blog, User, Comment, Post
from basehandler import Handler
"""
*
* Main Content Handlers
*
"""


class MainHandler(Handler):
    # Main Page Handler
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY "
                            "created DESC LIMIT 10")
        if self.getUser_Logged():
            self.render("home.html", log_text=Const.LOGOUT, posts=posts)
        else:
            self.render("home.html", log_text=Const.LOGIN, posts=posts)


class LoginHandler(Handler):
    # Login Page Handler
    def get(self):
        user = self.getUser_Logged()
        if user:
            self.resetCommentEditAuth()
            self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
            self.redirect("/")
        else:
            self.render("login.html", log_text=Const.LOGIN)

    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')

        if self.valid_username(username) and self.valid_password(password):
            blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
            user_key = db.Key.from_path('User',
                                        str(username),
                                        parent=blog.key())
            user = db.get(user_key)
            if user and self.valid_pw(username, password, user.password):
                username_hash = self.make_secure_val(username)
                self.response.headers.add_header('Set-Cookie',
                                                 'username=%s; Path=/' %
                                                 str(username_hash))
                self.redirect('/welcome')
                return

        params = {"error": "Invalid Username and/or Password",
                  "username": username,
                  "log_text": Const.LOGIN}
        self.render("login.html", **params)


class SignupHandler(Handler):
    # Signup Page Handler
    def get(self):
        self.render("signup.html", log_text=Const.LOGIN)

    def post(self):
        username = self.request.get('input_username')
        password = self.request.get('input_password')
        verify = self.request.get('input_verify')
        email = self.request.get('input_email')

        params = {"error_username": "",
                  "error_password": "",
                  "error_verify": "",
                  "error_email": "",
                  "username": username,
                  "email": email,
                  "log_text": "LOGIN"}

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
            password_encrypt = self.make_pw_hash(name=username, pw=password)
            blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
            new_user = User(parent=blog,
                            key_name=username,
                            username=username,
                            password=password_encrypt,
                            email=email)
            new_user.put()
            self.redirect('/login')
        else:
            self.render('signup.html', **params)


class NewPostHandler(Handler):
    # New Post Handler
    def get(self):
        if self.getUser_Logged():
            self.render("newpost.html", log_text=Const.LOGOUT)
        else:
            self.render("newpost.html", log_text=Const.LOGIN)

    def post(self):
        params = {"error": "",
                  "subject": "",
                  "content": "",
                  "log_text": ""}

        user = self.getUser_Logged()
        if not user:
            params["error"] = "You're not logged in!" \
                              "Please login before you post."
            params["log_text"] = "LOGIN"
        else:
            subject = self.request.get("subject")
            content = self.request.get("content")

            if not subject and not content:
                params["error"] = "You're missing a subject and the content"
            elif not subject:
                params["error"] = "You're missing a subject!"
            elif not content:
                params["error"] = "You're missing the content!"

            if not params["error"]:
                blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
                post = Post(parent=blog,
                            subject=subject,
                            author=user.username,
                            content=content)
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
                return

        self.render("newpost.html", **params)


class PostHandler(Handler):
    # Post Handler
    def get(self, post_id, comment_id=""):
        blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
        p_key = db.Key.from_path('Post', int(post_id), parent=blog.key())
        post = db.get(p_key)

        if not post:
            self.error(404)
            self.redirect('/')
            return

        self.initCommentEditAuth(post)

        comments = db.GqlQuery("SELECT * FROM Comment WHERE ANCESTOR IS :1 ",
                               post)

        params = {"log_text": "",
                  "post": post,
                  "like_enable": False,
                  "dislike_enable": False,
                  "comment_enable": False,
                  "comments": comments,
                  "edit_enable": False}

        user = self.getUser_Logged()
        if user:
            self.resetCommentEditEnable(comment_id)
            params["log_text"] = Const.LOGOUT
            params["comment_enable"] = True
            if not user.username == post.author:
                params["like_enable"] = True
                params["dislike_enable"] = True
            else:
                params["edit_enable"] = True
        else:
            params["log_text"] = Const.LOGIN

        self.render("post.html", **params)

    def post(self, post_id, edit=""):
        blog = Blog.get_by_key_name(Const.KEYNAME)
        p_key = db.Key.from_path('Post', int(post_id), parent=blog.key())
        post = db.get(p_key)

        if not post:
            self.error(404)
            return

        button_value = (self.request.get("input_button")).split(',')
        user = self.getUser_Logged()
        comment_id = ""

        if user:
            if button_value[0] == "like":
                if user.username != post.author:
                    if user.username in post.dislike_userlist:
                        post.dislikes -= 1
                        post.dislike_userlist.remove(user.username)
                    if user.username not in post.like_userlist:
                        post.likes += 1
                        post.like_userlist.append(user.username)
                    post.put()
            elif button_value[0] == "dislike":
                if user.username != post.author:
                    if user.username in post.like_userlist:
                        post.likes -= 1
                        post.like_userlist.remove(user.username)
                    if user.username not in post.dislike_userlist:
                        post.dislikes += 1
                        post.dislike_userlist.append(user.username)
                    post.put()
            elif button_value[0] == "comment":
                if self.getUser_Logged():
                    new_content = self.request.get("comment_text", "")
                    new_comment = Comment(parent=post,
                                          author=user.username,
                                          content=new_content,
                                          edit_auth=True)
                    new_comment.put()
            elif button_value[0] == "edit":
                if user.username == post.author:
                    self.redirect('/edit/%s' % str(post.key().id()))
                    return
            elif button_value[0] == "delete":
                if user.username == post.author:
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE "
                                           "ANCESTOR IS :1 ", post)
                    for comment in comments:
                        comment.delete()
                    post.delete()
                    self.redirect('/')
                    return
            elif button_value[0] == "editcomment":
                user = self.getUser_Logged()
                c_key = db.Key.from_path('Comment',
                                         int(button_value[1]),
                                         parent=post.key())
                comment = db.get(c_key)
                if comment and user.username == comment.author:
                    comment.edit_enable = True
                    comment_id = str(comment.key().id())
                    comment.put()
            elif button_value[0] == "deletecomment":
                c_key = db.Key.from_path('Comment',
                                         int(button_value[1]),
                                         parent=post.key())
                comment = db.get(c_key)
                user = self.getUser_Logged()
                if comment and user.username == comment.author:
                    comment.delete()
            elif button_value[0] == "submitcomment":
                user = self.getUser_Logged()
                c_key = db.Key.from_path('Comment',
                                         int(button_value[1]),
                                         parent=post.key())
                comment = db.get(c_key)
                if comment:
                    if user.username == comment.author:
                        comment.content = self.request.get("textarea-" +
                                                           button_value[1])
                        comment.edit_enable = False
                        comment.put()

        if comment_id:
            self.redirect('/post/%s/%s' % (str(post.key().id()), comment_id))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class EditHandler(Handler):
    def get(self, post_id):
        user = self.getUser_Logged()
        if user:
            blog = Blog.get_by_key_name(Const.KEYNAME)
            p_key = db.Key.from_path('Post', int(post_id), parent=blog.key())
            post = db.get(p_key)
            if post:
                if post.author == user.username:
                    params = {"subject": post.subject,
                              "content": post.content,
                              "log_text": Const.LOGOUT}
                    self.render('edit.html', **params)
                    return

        self.redirect('/post/%s' % post_id)

    def post(self, post_id):
        button_value = self.request.get("input_button")
        user = self.getUser_Logged()
        blog = Blog.get_by_key_name(Const.KEYNAME)
        key = db.Key.from_path('Post', int(post_id), parent=blog.key())
        post = db.get(key)

        if user.username == post.author and button_value == "submit":
            subject = self.request.get("subject")
            content = self.request.get("content")

            params = {"error": "",
                      "subject": subject,
                      "content": content,
                      "log_text": Const.LOGOUT}

            if not subject and not content:
                params["error"] = "You're missing a subject and the content"
            elif not subject:
                params["error"] = "You're missing a subject!"
            elif not content:
                params["error"] = "You're missing the content!"

            if params["error"]:
                self.render('newpost.html', **params)
            else:
                post.subject = subject
                post.content = content
                post.put()
        self.redirect('/post/%s' % str(post.key().id()))


class WelcomeHandler(Handler):
    def get(self):
        user = self.getUser_Logged()
        self.render("welcome.html",
                    username=user.username,
                    log_text=Const.LOGOUT)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/home', MainHandler),
    ('/login', LoginHandler),
    ('/signup', SignupHandler),
    ('/newpost', NewPostHandler),
    ('/post/([0-9]+)', PostHandler),
    ('/edit/([0-9]+)', EditHandler),
    ('/post/([0-9]+)/([0-9]+)', PostHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
