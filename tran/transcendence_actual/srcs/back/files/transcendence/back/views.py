from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .models import Match, Score, Tournament
from .serializers import UserSerializer, MatchSerializer, ScoreSerializer, TournamentSerializer
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm
from django.shortcuts import redirect
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
import os
from django.core.management import BaseCommand
from django.db import transaction
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from django.contrib.auth.decorators import login_required
from .forms import Enable2FAForm
from django.contrib.auth.views import LoginView

################ 2PA #################

# Vue pour la page d'accueil
def home(request):
    return render(request, 'home.html')

# Fonction pour générer et enregistrer la clé TOTP
def generate_totp_key():
    return random_hex(20)  # Génère une clé secrète hexadécimale de 20 octets

# Vue pour la page d'inscription
def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            totp_key = generate_totp_key()  # Génère une clé TOTP pour l'utilisateur
            user.totp_key = totp_key  # Enregistre la clé dans le modèle utilisateur
            user.save()
            
            # Ajoute automatiquement un périphérique TOTP pour l'utilisateur
            device = TOTPDevice.objects.create(user=user, key=totp_key)
            device.save()

            # Authentifie et connecte l'utilisateur nouvellement inscrit
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)

            return redirect('enable_2fa')  # Rediriger vers la page d'accueil après l'inscription
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})


# Vue pour la page de connexion
def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('verify_2fa')  # Rediriger vers la page de 2Fa avant la page d'accueil après la connexion
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

# Vue pour la modification de mot de passe
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Garder l'utilisateur connecté
            return redirect('password_change_done')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change-password/change_password.html', {'form': form})

# Vue pour la confirmation de modification de mot de passe
def password_change_done(request):
    return render(request, 'change-password/password_change_done.html')

def user_logout(request):
    logout(request)
    return redirect('login')  # Redirection vers votre page de connexion HTML (nommée 'login' dan

# Create a view that allows users to enable 2FA for their accounts. 
# You can use Django’s class-based views for this purpose. 


@login_required
def enable_2fa(request):
    if request.method == 'POST':
        form = Enable2FAForm(request.user, request.POST)
        if form.is_valid():
            # Enable 2FA for the user
            device = TOTPDevice.objects.create(user=request.user)
            device.save()
            # Redirect to verification page
            return redirect('index')
    else:
        form = Enable2FAForm(request.user)

    # Generate QR code URL
    totp_device = TOTPDevice.objects.get_or_create(user=request.user)[0]
    qr_code_url = totp_device.config_url

    return render(request, 'enable_2fa.html', {'form': form, 'qr_code_url': qr_code_url})

@login_required
def verify_2fa(request):
    if request.method == 'POST':
        # Handle the 2FA verification form submission
        return redirect('index') #TOTPVerificationView.as_view()(request)

    devices = TOTPDevice.objects.filter(user=request.user)
    return render(request, 'verify_2fa.html', {'devices': devices})

from django.shortcuts import render

def success_page(request):
    # Logique de la vue pour la page de succès
    return render(request, 'index.html')

#To make use of 2FA, you need to update your user authentication 
# views, such as the login view. Here’s an example of how you can 
# modify the login view to incorporate 2FA verification

class CustomLoginView(LoginView):
    template_name = 'login.html'

    def form_valid(self, form):
        # Check if the user has 2FA enabled
        user = self.request.user
        if TOTPDevice.objects.filter(user=user).count() > 0:
            # Redirect to the 2FA verification view
            return redirect('verify_2fa')

        # Continue with regular login
        return super().form_valid(form)


################ GAME #################

def index(request):
    return render(request, "index.html")

def jeu(request):
    return render(request, "jeu.html")

def tournoi(request):
    return render(request, "tournoi.html")

def ordinateur(request):
    return render(request, "ordinateur.html")

# @api_view(['POST'])
# def signup(request):
#     form = CustomUserCreationForm(request.POST)
#     if form.is_valid():
#         user = form.save()
#         return Response(form.data, status=status.HTTP_201_CREATED)
#     return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def user_list(request):
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def user_detail(request, pk):
    try:
        user = 0
        if (pk.isnumeric()):
            user = User.objects.get(pk=pk)
        if (not user):
            user = User.objects.get(username=pk)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def match_list(request):
    if request.method == 'GET':
        matchs = Match.objects.all()
        serializer = MatchSerializer(matchs, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = MatchSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def match_detail(request, pk):
    try:
        match = Match.objects.get(pk=pk)
    except Match.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if request.method == 'GET':
        serializer = MatchSerializer(match)
        return Response(serializer.data)


@api_view(['GET', 'POST'])
def tournament_list(request):
    if request.method == 'GET':
        tournaments = Tournament.objects.all()
        serializer = TournamentSerializer(tournaments, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = TournamentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def tournament_detail(request, pk):
    try:
        tournament = Tournament.objects.get(pk=pk)
    except Tournament.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if request.method == 'GET':
        serializer = TournamentSerializer(tournament)
        return Response(serializer.data)
    elif request.method == 'PUT':
        if (not request.data.get('players')):
            players = tournament.players.values_list('nickname', flat=True)
            request.data['players'] = players
        serializer = TournamentSerializer(tournament, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)