# from django import forms
# from django.contrib.auth.models import User
# from django.contrib.auth.forms import UserCreationForm

# class CustomUserCreationForm(UserCreationForm):
#     first_name = forms.CharField(max_length=30, required=True, help_text='Required. Enter your first name.')
#     last_name = forms.CharField(max_length=30, required=True, help_text='Required. Enter your last name.')

#     class Meta:
#         model = User
#         fields = [
#             'username', 
#             'first_name', 
#             'last_name', 
#             'email', 
#             'password1', 
#             'password2', 
#         ]

# Importation des classes nécessaires depuis le module forms de Django
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

# Définition d'une classe de formulaire personnalisée pour la création d'utilisateurs
class CustomUserCreationForm(UserCreationForm):
    # Définition des champs supplémentaires pour le formulaire
    first_name = forms.CharField(max_length=30, required=True, help_text='Required. Enter your first name.')
    last_name = forms.CharField(max_length=30, required=True, help_text='Required. Enter your last name.')

    class Meta:
        # Spécification du modèle associé au formulaire
        model = User
        # Définition des champs à inclure dans le formulaire et leur ordre
        fields = [
            'username',        # Nom d'utilisateur
            'first_name',      # Prénom
            'last_name',       # Nom de famille
            'email',           # Adresse e-mail
            'password1',       # Mot de passe
            'password2',       # Confirmation du mot de passe
        ]

# À l'intérieur du constructeur, nous appelons d'abord le constructeur de la 
# classe parente pour nous assurer que toutes les fonctionnalités de base du 
# formulaire sont initialisées correctement. Ensuite, nous ajoutons un champ 
# au formulaire en utilisant self.fields['nom_du_champ'] = .... Dans ce cas, 
# nous ajoutons un champ de type CharField avec le label 'Verification Code' 
# et une longueur maximale de 6 caractères.

from django import forms

class Enable2FAForm(forms.Form):
    def __init__(self, user, *args, **kwargs):
        # Initialisation du formulaire avec l'utilisateur en cours
        super(Enable2FAForm, self).__init__(*args, **kwargs)
        
        # Ajout du champ de vérification du code
        self.fields['verification_code'] = forms.CharField(label='Verification Code', max_length=6)

