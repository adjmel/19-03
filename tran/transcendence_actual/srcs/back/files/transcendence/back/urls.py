from django.urls import path
from . import views
# Importation de la fonction path pour définir les URLs et des vues nécessaires
from django.urls import path
# Importation des vues définies dans le même répertoire que ce fichier
from . import views
# Importation des vues d'authentification de Django
from django.contrib.auth import views as auth_views
from django_otp.admin import OTPAdminSite
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_totp.admin import TOTPDeviceAdmin
from .views import CustomLoginView, verify_2fa

urlpatterns = [

#2FA
# URL de la page d'accueil
    # path('', views.home, name='home'),
        # URL de la page de connexion (utilisant une vue personnalisée)
    path('', views.user_login, name='login'),
    # Configuration de l'administration Django avec OTPAdminSite
    # path('admin/', admin_site.urls),
    
    path('enable_2fa/', views.enable_2fa, name='enable_2fa'),
    path('verify_2fa/', views.verify_2fa, name='verify_2fa'),
    # path('generate_qr_code/', views.generate_qr_code, name='generate_qr_code'),
# path('login/', views.CustomLoginView, name='login'),

    # URL de la page d'inscription
    path('signup/', views.signup, name='signup'),

    # URL de la page de déconnexion (utilisant la vue de déconnexion intégrée de Django)
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    # URL pour changer de mot de passe
    path('change_password/', views.change_password, name='change_password'),
    # URL de la page de confirmation de changement de mot de passe
    path('password_change_done/', views.password_change_done, name='password_change_done'),
    # URL pour réinitialiser le mot de passe
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='password-reset/password_reset_form.html',
        email_template_name='password-reset/password_reset_email.html',
        subject_template_name='password-reset/password_reset_subject.txt',
        success_url='/password_reset_done/'
    ), name='password_reset'),
    # URL de la page de confirmation d'envoi de l'email de réinitialisation de mot de passe
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(
        template_name='password-reset/password_reset_done.html'
    ), name='password_reset_done'),
    # URL de la page pour confirmer la réinitialisation de mot de passe
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='password-reset/password_reset_confirm.html',
        success_url='/password_reset_complete/'
    ), name='password_reset_confirm'),
    # URL de la page de confirmation de réinitialisation de mot de passe
    path('password_reset_complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='password-reset/password_reset_complete.html'
    ), name='password_reset_complete'),

    #game
    path("index/", views.index, name='index'),
    path("jeu/", views.jeu, name='jeu'),
    path("tournoi/", views.tournoi, name='tournoi'),
    path("ordinateur/", views.ordinateur, name='ordinateur'),
    path('users/', views.user_list, name='user_list'),
    path('users/<slug:pk>/', views.user_detail, name='user_detail'),
    path('matchs/', views.match_list, name='match_list'),
    path('matchs/<int:pk>/', views.match_detail, name='match_detail'),
    path('tournaments/', views.tournament_list, name='tournament_list'),
    path('tournaments/<int:pk>/', views.tournament_detail, name='tournament_detail'),
]
