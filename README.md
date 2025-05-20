Deployment link: http://35.200.136.252:8080/

For local setup:
1. Open docker desktop, open the terminal
2. Clone the repo:  
      git clone https://github.com/vedanshbvb/crossbow_webhook_delivery.git
4. Build and start the containers:  
      cd crossbow_webhook_delivery  
      docker-compose up --build
6. Open a gitbash in the terminal window, run migrations:  
      cd crossbow_webhook_delivery  
      docker-compose exec web python manage.py migrate
8. Access the application at:  
      http://localhost:8080

video demos: https://drive.google.com/drive/folders/19xUze09-YtprMSHmp77FV18-F736Bmio?usp=sharing  
For README, please read README_crossbow.pdf
