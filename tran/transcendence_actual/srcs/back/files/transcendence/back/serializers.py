from rest_framework import serializers
from .models import Score, Match, Tournament
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email']

class ScoreSerializer(serializers.ModelSerializer):
    score = serializers.IntegerField()
    player = serializers.SlugRelatedField(
        many=False, 
        read_only=False,
        queryset=User.objects.all(),
        slug_field='username'
    )

    class Meta:
        model = Score
        fields = ['player', 'score']

class MatchSerializer(serializers.ModelSerializer):
    scores = ScoreSerializer(many=True)
    player_nbr = serializers.IntegerField(default=2, required=False)
    winner = serializers.SlugRelatedField(
        many=False, 
        read_only=False,
        queryset=User.objects.all(),
        slug_field='username'
    )
    tournament = serializers.PrimaryKeyRelatedField(
        many=False, 
        read_only=False,
        queryset=Tournament.objects.all(),
        allow_null=True,
        required=False
    )

    class Meta:
        model = Match
        fields = ['winner', 'tournament', 'player_nbr', 'scores']
    
    def validate_player_nbr(self, data):
        if (data < 2):
            raise serializers.ValidationError({"player_nbr": "player number must be higher than 2"})
        return data
    
    def validate(self, data):
        scores = data['scores']
        if (len(scores) != data['player_nbr']):
            raise serializers.ValidationError({"scores": "there must be as much scores as players"})
        return data
    
    def create(self, validated_data):
        scores = validated_data.pop('scores')
        match_instance = Match.objects.create(**validated_data)
        for score in scores:
            Score.objects.create(match=match_instance,**score)
        return match_instance


class TournamentSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=30)
    players = serializers.SlugRelatedField(
        many=False, 
        read_only=False,
        queryset=User.objects.all(),
        slug_field='username'
    )
    winner = serializers.SlugRelatedField(
        many=False, 
        read_only=False,
        queryset=User.objects.all(),
        slug_field='username',
        allow_null=True,
        required=False
    )

    class Meta:
        model = Tournament
        fields = ['name', 'winner','players']

    def validate(self, data):
        players = data.get('players')
        winner = data.get('winner')
        if (players and winner and winner not in players):
            raise serializers.ValidationError({"winner": "winner needs to be one of the players"})
        return data