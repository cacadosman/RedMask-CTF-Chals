sudo docker build -t wtube_backend:latest -f Dockerfile.app .
sudo docker build -t wtube_server:latest -f Dockerfile.nginx .
sudo docker stack deploy --compose-file=docker-compose.yml wtube
