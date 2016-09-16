import os
import webapp2
import datamodels
import datatools

class EditHandler(Handler):
    def get(self, post_id):
        if getUser_Logged():
            blog = Blog.get_by_key_name(KEYNAME)
            p_key = db.Key.from_path('Post', int(post_id), parent = blog.key())
            post = db.get(p_key)

            params = {"subject" : post.subject, "content" : post.content}
            self.render('edit.html', **params)
        else:
            self.redirect('/post/%s' % str(post.key().id()))

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