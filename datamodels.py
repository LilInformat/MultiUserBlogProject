from google.appengine.ext import db

# Database Classes


class Blog(db.Model):
    name = db.StringProperty(required=True)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    likes = db.IntegerProperty(default=0)
    dislikes = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)

    like_userlist = db.StringListProperty(default=None)
    dislike_userlist = db.StringListProperty(default=None)


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)


class Comment(db.Model):
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    edit_auth = db.BooleanProperty(default=False)
    edit_enable = db.BooleanProperty(default=False)
    created = db.DateTimeProperty(auto_now_add=True)

