'use strict';

let id = 0;
let nb_games = 0;
let launchTornament;
let username;
let btn_participate;
let loginForm;
let playersArr2;
var game;
var anim;
let canvas2;
let playerName1;
let playerName2;
let nextbtn;
let it = 0;
let winnersArr = [];



const PLAYER_HEIGHT2 = 100;
const PLAYER_WIDTH2 = 5;
const MAX_SPEED2 = 12;

setTimeout(function() {
    launchTornament = document.getElementById("btn-launch-game");
    btn_participate = document.getElementById("btn-participer");
    loginForm = document.getElementById("loginForm");
    username = document.getElementById("username");
    btn = document.getElementById("btn-1");
    if (launchTornament && username && btn_participate && loginForm)  {
        loginForm.addEventListener('submit', function(e) {
          participateTournament(e);
        });
        launchTornament.addEventListener('click', function(e) {
          launchTourn(e);
        });
        return;
    }
}, 1000);

function checkInput(username)
{
    var myLists = document.getElementsByTagName('li');

    for(var i = 0; i < myLists.length; i++)
    {
        if(myLists[i].innerHTML == username.value)
            return 1;
    }
    return 0;
}

function launchTourn(e){
  e.preventDefault();
  if(id % 2 == 1)
    alert("We have to wait for another player to participate");
  else
  {
    if(id < 2)
    {
      alert("We have to wait for another player to participate");
      return;
    }
    let playersArr = [];
    let it = 0;
    while (it < id) {
        playersArr.push(it);
        it++;
    }
    playersArr2 = new Map();
    while(playersArr.length)
    {
      var player1 = generatePlayer(playersArr, id);
      playersArr.splice(playersArr.indexOf(player1), 1);
      var player2 = generatePlayer(playersArr, id);
      playersArr.splice(playersArr.indexOf(player2), 1);
      console.log(document.getElementById("joueur_" + player1).innerHTML + " is going to confront " + document.getElementById("joueur_" + player2).innerHTML);
      playersArr2.set("player" + nb_games + "_0", document.getElementById("joueur_" + player1).innerHTML);
      playersArr2.set("player" + nb_games + "_1", document.getElementById("joueur_" + player2).innerHTML);
      nb_games++;
    } 
  }
  if(nb_games)
    begin_tornaments();
}

function isValidUsername(nom) 
{
  // Expression régulière pour autoriser seulement les lettres, les chiffres, les tirets et les underscores
  var regex = /^[a-zA-Z0-9_\-]+$/;
  // Vérifie si le nom d'utilisateur correspond à l'expression régulière
  return 1;
}

function participateTournament(e) {
  e.preventDefault();
  if (!isValidUsername(username)) 
  {
    // Empêche l'envoi du formulaire si la validation échoue
    // Affiche un message d'erreur à l'utilisateur
    alert("The username is invalid. Please do not use special characters.");
  }
  else if (username.value == "") {
    alert("Ensure you input a value in both fields!");
    return;
  } 
  else if(checkInput(username) == 1)
  {
    alert("username already used!");
    return;

  }
  else {
    addElement(username.value);
    id++;
    username.value = "";
    return;

  }
}


function addElement(element)
{
    const newUser = document.createElement("li");
    const newContent = document.createTextNode(element);
    newUser.appendChild(newContent);

    const username = document.getElementById("player-list");
    
    username.appendChild(newUser);

    newUser.setAttribute("id", "joueur_" + id);
    newUser.setAttribute("className", element);
}


var namePlayer = "";

function isInArr(arr, num)
{
  var i = 0;
  while(arr[i] != null)
  {
    if(arr[i] == num)
      return 1;
    i++;
  }
  return(0);
}

function generatePlayer(arr, id){
    var num = Math.floor(Math.random() * id);
    while(isInArr(arr, num) == 0)
      num = Math.floor(Math.random() * id);;
    return(num);
}

function loadGamePage(player1, player2){
  const request = new XMLHttpRequest();
  const container = document.getElementById("container");
  request.open("GET", "pages/jeu/index.html");
  request.send();
  request.onload = function()
  {
    if(request.status == 200)
      container.innerHTML = request.responseText;
    setTimeout(function() {
      canvas2 = document.getElementById("canvas");
      playerName1 = document.getElementById("joueur1");
      playerName2 = document.getElementById("joueur2");
      console.log("loading...");
      if (canvas2 && playerName1 && playerName2) {
        playerName1.innerHTML = player1;
        playerName2.innerHTML = player2;
        console.log("loaded...");
        startCanva();
      }
    }, 100);
  }
}


function oneGame(it) {
  var player1 = playersArr2.get("player" + it + "_0");
  var player2 = playersArr2.get("player" + it + "_1");
  console.log("first game: " + player1 + " vs " + player2);
  loadGamePage(player1, player2);
}

function begin_tornaments() {
  const element = document.getElementById("div-tournoi");
  element.remove();
  oneGame(it);
}

function displayWin(score1, score2) {
  const element = document.getElementById("jeu-div");
  // element.remove();
  
  const newUser = document.createElement("p");
  const newContent = document.createTextNode(element);
  newUser.appendChild(newContent);

  const newBtn = document.createElement("button");
  const newDiv = document.createTextNode(element);
  newBtn.appendChild(newDiv);
  newBtn.setAttribute("id", "next-btn");


  const username = document.getElementById("container");
  if(score1 > 2)
  {
    newUser.innerHTML = playerName1.innerHTML + " HAS WON";
    winnersArr.push(playerName1.innerHTML);
    console.log(playerName1.innerHTML + " HAS WON");
  }
  else
  {
    newUser.innerHTML = playerName2.innerHTML + " HAS WON";
    winnersArr.push(playerName2.innerHTML);
    console.log(playerName2.innerHTML + " HAS WON");
  }
  newBtn.innerHTML = "Suivant";

  username.appendChild(newUser);
  username.appendChild(newBtn);

  setTimeout(() => {
    
  }, 10000);
  if(it < nb_games - 1)
  {
    console.log("it: " + it + " nb_games: " + nb_games);
    var nextbtn = document.getElementById("next-btn");
    nextbtn.addEventListener('click', function() {
        oneGame(++it);
    });
  }
  else
  {
    var nextbtn = document.getElementById("next-btn");
    nextbtn.addEventListener('click', function() {
        winnersDisplay();
    });
  }
  
}

function winnersDisplay() {
  const element = document.getElementById("jeu-div");
  element.remove();

  const elt = document.getElementById("container");
  
  const winnersUser = document.createElement("p");
  var newContent = document.createTextNode("Winners are: ");
  winnersUser.appendChild(newContent);
  var i = 0;
  while(winnersArr[i])
  {
    console.log(winnersArr[i]);
    newContent = document.createTextNode(winnersArr[i] + ", ");
    winnersUser.appendChild(newContent);
    i++;
  }

  elt.appendChild(winnersUser);
}

/* GAME PART */

function startCanva() {
    
    game = {
        player: {
            score: 0
        },
        computer: {
            score: 0,
            speedRatio: 0.75
        },
        ball: {
            r: 5,
            speed: {}
        }
    };
    draw();
    reset();
    // Mouse move event
    document.addEventListener('keydown', playerMove);
    document.addEventListener('keydown', player2Move);
    // Mouse click event
    document.querySelector('#start-game').addEventListener('click', play);
    // document.querySelector('#stop-game').addEventListener('click', stop);
}

function draw() {
    const canvas2 = document.getElementById("canvas");
    var context = canvas2.getContext('2d');

    // Draw field
    context.fillStyle = 'black';
    context.fillRect(0, 0, canvas2.width, canvas2.height);

    // Draw middle line
    context.strokeStyle = 'white';
    context.beginPath();
    context.moveTo(canvas2.width / 2, 0);
    context.lineTo(canvas2.width / 2, canvas2.height);
    context.stroke();

    // Draw players
    context.fillStyle = 'white';
    context.fillRect(0, game.player.y, PLAYER_WIDTH2, PLAYER_HEIGHT2);
    context.fillRect(canvas2.width - PLAYER_WIDTH2, game.computer.y, PLAYER_WIDTH2, PLAYER_HEIGHT2);

    // Draw ball
    context.beginPath();
    context.fillStyle = 'white';
    context.arc(game.ball.x, game.ball.y, game.ball.r, 0, Math.PI * 2, false);
    context.fill();
}

function changeDirection(playerPosition) {
    var impact = game.ball.y - playerPosition - PLAYER_HEIGHT2 / 2;
    var ratio = 100 / (PLAYER_HEIGHT2 / 2);

    // Get a value between 0 and 10
    game.ball.speed.y = Math.round(impact * ratio / 10);
}

function playerMove(event) 
{
    canvas2 = document.getElementById("canvas");
    if(event.code == 'ArrowDown' && game.player.y < canvas2.height - PLAYER_HEIGHT2)
        game.player.y += 20;
    else if(event.code == 'ArrowUp' && game.player.y > 0)
        game.player.y -= 20;

}

function player2Move(event) 
{
  canvas2 = document.getElementById("canvas");
    if(event.code == 'KeyS' && game.computer.y < canvas2.height - PLAYER_HEIGHT2)
        game.computer.y += 20;
    else if(event.code == 'KeyW' && game.computer.y > 0)
        game.computer.y -= 20;

}

function collide(player) {
    // The player does not hit the ball
    if (game.ball.y < player.y || game.ball.y > player.y + PLAYER_HEIGHT2) {
        if (player == game.player) {
            game.computer.score++;
            document.querySelector('#computer-score').textContent = game.computer.score;
        } else {
            game.player.score++;
            document.querySelector('#player-score').textContent = game.player.score;
        }
    } else {
        // Change direction
        game.ball.speed.x *= -1;
        changeDirection(player.y);

        // Increase speed if it has not reached max speed
        if (Math.abs(game.ball.speed.x) < MAX_SPEED2) {
            game.ball.speed.x *= 1.2;
        }
    }
}

function ballMove() {
  canvas2 = document.getElementById("canvas");
    if(!canvas2)
      return;
    // Rebounds on top and bottom
    if (game.ball.y > canvas2.height || game.ball.y < 0) {
        game.ball.speed.y *= -1;
    }

    if (game.ball.x > canvas2.width - PLAYER_WIDTH2) {
        collide(game.computer);
    } else if (game.ball.x < PLAYER_WIDTH2) {
        collide(game.player);
    }

    game.ball.x += game.ball.speed.x;
    game.ball.y += game.ball.speed.y;
}

function play() {
    draw();

    // computerMove(); //pour l'IA
    ballMove();

    anim = requestAnimationFrame(play);

    if(game.computer.score > 2 || game.player.score > 2)
    {
      stop();
      return;
    }
}

function reset() {
  console.log("RESET");
  canvas2 = document.getElementById("canvas");
  // Set ball and players to the center
  game.ball.x = canvas2.width / 2;
  game.ball.y = canvas2.height / 2;
  game.player.y = canvas2.height / 2 - PLAYER_HEIGHT2 / 2;
  game.computer.y = canvas2.height / 2 - PLAYER_HEIGHT2 / 2;
  // Reset speed
  game.ball.speed.x = 3;
  game.ball.speed.y = Math.random() * 3;
}

function stop() {
  console.log("STOP");
    cancelAnimationFrame(anim);
    reset();
    // Init score
    game.computer.score = 0;
    game.player.score = 0;

    document.querySelector('#computer-score').textContent = game.computer.score;
    document.querySelector('#player-score').textContent = game.player.score;

    draw();
    displayWin(game.computer.score, game.player.score);
    return;
}