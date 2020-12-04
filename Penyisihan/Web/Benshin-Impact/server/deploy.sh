sudo docker build -t benshin_app:latest -f Dockerfile .
sudo docker stack deploy --compose-file=docker-compose.yml benshin
