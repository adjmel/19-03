'use strict';
var canvas3;
var btn_start;
var game;
var anim;


const PLAYER_HEIGHT3 = 100;
const PLAYER_WIDTH3 = 5;
const MAX_SPEED3 = 12;

setTimeout(function() {
    btn_start = document.getElementById("start-game");
    canvas3 = document.getElementById("canvas2");
    btn = document.getElementById("btn-1");
    if (btn_start && canvas3) {
        startGame();
    }
}, 1000);


function startGame() {
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
    drawCanvas();
    reset();

    // Mouse move event
    document.addEventListener('keydown', playerMove);

    // Mouse click event
    document.querySelector('#start-game').addEventListener('click', play);
    document.querySelector('#stop-game').addEventListener('click', stop);

};

function drawCanvas() {
    canvas3 = document.getElementById("canvas2");
    console.log(canvas3);
    var context = canvas3.getContext('2d');

    // Draw field
    context.fillStyle = 'black';
    context.fillRect(0, 0, canvas3.width, canvas3.height);

    // Draw middle line
    context.strokeStyle = 'white';
    context.beginPath();
    context.moveTo(canvas3.width / 2, 0);
    context.lineTo(canvas3.width / 2, canvas3.height);
    context.stroke();

    // Draw players
    context.fillStyle = 'white';
    context.fillRect(0, game.player.y, PLAYER_WIDTH3, PLAYER_HEIGHT3);
    context.fillRect(canvas3.width - PLAYER_WIDTH3, game.computer.y, PLAYER_WIDTH3, PLAYER_HEIGHT3);

    // Draw ball
    context.beginPath();
    context.fillStyle = 'white';
    context.arc(game.ball.x, game.ball.y, game.ball.r, 0, Math.PI * 2, false);
    context.fill();
}

function changeDirection(playerPosition) {
    var impact = game.ball.y - playerPosition - PLAYER_HEIGHT3 / 2;
    var ratio = 100 / (PLAYER_HEIGHT3 / 2);

    // Get a value between 0 and 10
    game.ball.speed.y = Math.round(impact * ratio / 10);
}

function playerMove(event) 
{
    if(event.code == 'ArrowDown' && game.player.y < canvas3.height - PLAYER_HEIGHT3)
        game.player.y += 20;
    else if(event.code == 'ArrowUp' && game.player.y > 0)
        game.player.y -= 20;

}
function computerMove() {
    game.computer.y += game.ball.speed.y * game.computer.speedRatio;
}

function collide(player) {
    // The player does not hit the ball
    if (game.ball.y < player.y || game.ball.y > player.y + PLAYER_HEIGHT3) {
        reset();

        // Update score
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
        if (Math.abs(game.ball.speed.x) < MAX_SPEED3) {
            game.ball.speed.x *= 1.2;
        }
    }
}

function ballMove() {
    // Rebounds on top and bottom
    if (game.ball.y > canvas3.height || game.ball.y < 0) {
        game.ball.speed.y *= -1;
    }

    if (game.ball.x > canvas3.width - PLAYER_WIDTH3) {
        collide(game.computer);
    } else if (game.ball.x < PLAYER_WIDTH3) {
        collide(game.player);
    }

    game.ball.x += game.ball.speed.x;
    game.ball.y += game.ball.speed.y;
}

function play() {
    drawCanvas();

    computerMove();
    ballMove();

    anim = requestAnimationFrame(play);
}

function reset() {
    // Set ball and players to the center
    game.ball.x = canvas3.width / 2;
    game.ball.y = canvas3.height / 2;
    game.player.y = canvas3.height / 2 - PLAYER_HEIGHT3 / 2;
    game.computer.y = canvas3.height / 2 - PLAYER_HEIGHT3 / 2;

    // Reset speed
    game.ball.speed.x = 3;
    game.ball.speed.y = Math.random() * 3;
}

function stop() {
    cancelAnimationFrame(anim);

    reset();

    // Init score
    game.computer.score = 0;
    game.player.score = 0;

    document.querySelector('#computer-score').textContent = game.computer.score;
    document.querySelector('#player-score').textContent = game.player.score;

    drawCanvas();
}