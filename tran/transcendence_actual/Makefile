all: up

up:
		@docker compose -f srcs/docker-compose.yml up -d --build

down:
		@docker compose -f srcs/docker-compose.yml down

clean: down
		@docker volume rm srcs_postgres
		@docker image rm srcs-back postgres:16.2

.PHONY: all up down clean