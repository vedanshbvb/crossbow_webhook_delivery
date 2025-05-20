Deployment link: http://35.200.136.252:8080/

For local setup:
1. Open docker desktop, open the terminal
2. Clone the repo: git clone https://github.com/vedanshbvb/crossbow_webhook_delivery.git
3. Build and start the containers: docker-compose up --build
4. Open gitbash, in the terminal window, run migrations: docker-compose exec web python manage.py migrate
5. Access the application at: http://localhost:8080
   
For README, please read README_crossbow.pdf
