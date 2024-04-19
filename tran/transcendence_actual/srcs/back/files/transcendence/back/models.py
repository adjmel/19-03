from django.db import models
from django.contrib.auth.models import User

#class User(models.Model):
    #nickname = models.CharField(max_length=30, primary_key=True)
    #name = models.CharField(max_length=30)
    #password = models.CharField(max_length=30)
    #created_at = models.DateTimeField(auto_now_add=True)
    #updated_at = models.DateTimeField(auto_now=True)

class Match(models.Model):
    player_nbr = models.IntegerField(default=2)
    winner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
    )
    tournament = models.ForeignKey(
        "Tournament",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Score(models.Model):
    player = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
    )
    score = models.IntegerField()
    match = models.ForeignKey(
        "Match",
        related_name='scores',
        on_delete=models.CASCADE,
    )

class Tournament(models.Model):
    name = models.CharField(max_length=30)
    players = models.ManyToManyField(User)
    winner = models.ForeignKey(
        User,
        related_name='tournament_winner',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

from django.db import models

#In your app’s models.py, create a UserProfile model to store 
#user-specific 2FA information:

from django.contrib.auth.models import User
from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    devices = models.ManyToManyField(TOTPDevice)


