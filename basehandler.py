import os
import webapp2
import jinja2

from common import Const
from datatools import Encryption, InputVerification
from datamodels import db, Blog, User, Comment, Post

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

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
        """
        Method Name: getUser_Logged()
        Return: Function returns user object if the user is currently logged in or returns None
        """
        username_str = self.request.cookies.get('username')
        if username_str:
            username_val = self.check_secure_val(username_str)
            if username_val:
                blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
                user_key = db.Key.from_path('User', str(username_val), parent=blog.key())
                user = db.get(user_key)
                if user:
                    return user
        return None

    def getUser(self, username=""):
        """
        Method Name: getUser()
        Return: Function returns a unit object that has the same username or returns None
        """
        if username:
            blog = Blog.get_or_insert(Const.KEYNAME, name="Udacity")
            user_key = db.Key.from_path('User', str(username), parent=blog.key())
            user = db.get(user_key)
            if user:
                return user
        return None

    def initCommentEditAuth(self, post):
        """
        Method Name: initCommentEditAuth()
        Funcionality: authorization of a logged in user to edit their own comments
        """
        user = self.getUser_Logged()
        if user:
            comments = db.GqlQuery(
                """
                SELECT * FROM Comment WHERE author = :username AND
                ANCESTOR IS :c_parent
                """ \
                , c_parent=post, username=user.username)
            for comment in comments:
                comment.edit_auth = True
                comment.put()

    def resetCommentEditAuth(self):
        """
        Method Name: resetCommentEditAuth()
        Functionality: removes authorization of editing any comments
        """
        comments = db.GqlQuery("SELECT * FROM Comment WHERE edit_auth = True")
        for comment in comments:
            comment.edit_auth = False
            comment.put()

    def resetCommentEditEnable(self, comment_id=""):
        """
        Method Name: resetCommentEditEnable
        Functionality: resets edit status of all comments other than specified comment
        """
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