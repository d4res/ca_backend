sudo cp ca_dev.conf /etc/nginx/sites-enabled/ca_dev.conf;
source config.sh
cd ../
flask run 
systemctl restart nginx