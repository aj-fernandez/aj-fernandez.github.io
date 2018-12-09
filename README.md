# aj-fernandez.github.io
![alt text](https://upload.wikimedia.org/wikipedia/commons/thumb/6/64/Solar-System.pdf/page1-3897px-Solar-System.pdf.jpg)

# Installing Elastichsearch on Hewlett Packard ML350 G5 x2 XEON 8 GB
![alt text](https://ydevs.com/wp-content/uploads/2017/10/logos-stack-elk.png)
### Update and install required packages

	sudo apt update && apt-get -y upgrade
	sudo apt install apt-transport-https software-properties-common wget

### Install jdk oracle java (required by Elastichsearch & Kibana)

	sudo apt install openjdk-8-jdk

	wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
	echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
	
	sudo apt update
	sudo apt install elasticsearch

### Limiting listen interfaces for Elasticsearch (not required xD)

 Edit /etc/elasticsearch/elasticsearch.yml

	network.host: localhost (localhost can be changed for an IP)

### Restart Elasticsearch for load changes and enable for load at new boots

	systemctl restart elasticsearch
	systemctl enable elasticsearch

### Checking the installation of Elasticsearch, this must show a JSON doc

	curl -X GET http://localhost:9200

### Install plugin required for Apache2 and Nginx modules among others:

On: /usr/share/elasticsearch
	
	bin/elasticsearch-plugin install ingest-user-agent
	bin/elasticsearch-plugin install ingest-geoip

### Installing Kibana (This part od the ELK stack build graphics and statictics, listen on 5601)

	apt install kibana

### Restricting remote access to Kibana
	
Edit /etc/kibana/kibana.yml
	
	server.host: "localhost"

### Restart Kibana for load changes and enable for load at new boots

	systemctl restart kibana
	systemctl enable kibana

### Usin Nginx like reverse proxy to access Kibana from public IP

Intall Nginx web server

	apt install nginx
	
 Basic authentication file with openssl command

		echo "admin:$(openssl passwd -apr1 typeHereThePassword)" | sudo tee -a /etc/nginx/htpasswd.kibana

This is a virtual host config file, delete default and create /etc/nginx/sites-available/kibana:
		
		server {
		    listen 80 default_server;
		    server_name _;
		    return 301 https://$server_name$request_uri;
		}

		server {
		    listen 443 default_server ssl http2;
 
		    server_name _;
 
		    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
		    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
		    ssl_session_cache shared:SSL:10m;
 
		    auth_basic "Restricted Access";
		    auth_basic_user_file /etc/nginx/htpasswd.kibana;
 
		    location / {
		        proxy_pass http://localhost:5601;
		        proxy_http_version 1.1;
		        proxy_set_header Upgrade $http_upgrade;
		        proxy_set_header Connection 'upgrade';
		        proxy_set_header Host $host;
		        proxy_cache_bypass $http_upgrade;
		    }
		}

Activate this site creating the simbolic link, test it and restart&enabling:

		sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/kibana
		sudo nginx -t
		sudo systemctl restart nginx
		sudo systemctl enable nginx

### Install Logstash, restart&enabling
	
	sudo systemctl restart logstash
	sudo systemctl enable logstash
	
	Config file used by default: /etc/logstash/startup.options
	
Validating Logstash setup

		sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t

### Install Filebeat on forwarders-nodes (https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-configuration.html)

Home path: [/usr/share/filebeat] Config path: [/etc/filebeat] Data path: [/var/lib/filebeat] Logs path: [/var/log/filebeat]
	
	curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.5.2-amd64.deb
 
	sudo dpkg -i filebeat-6.5.2-amd64.deb

	systemctl status filebeat

	systemctl enable filebeat

 Config host.elastichsearch in /etc/filebeat/filebeat.yml:

	output.elasticsearch:
	  hosts: ["myEShost:9200"]

Add credentials if elasctichsearch or kibana have been secured:
		
		output.elasticsearch:
		  hosts: ["myEShost:9200"]
		  username: "filebeat_internal"
		  password: "typePassword" 

		setup.kibana:
		  host: "mykibanahost:5601"
		  username: "myKibanaUser"  
		  password: "typePassword"

### Enable modules that you want to run

	filebeat modules enable system nginx mysql apache2 etc
	
To see a list of enabled and disabled modules:
		
		filebeat modules list

Config modules: /etc/filebeat/modules.d/system.yml

### Set up initial environment.

	filebeat setup -e

The setup command loads the recommended index template for writing to Elasticsearch and deploys the sample dashboards (if available) for visualizing the data in Kibana. This is a one-time setup step.

The -e flag is optional and sends output to standard error instead of syslog.

After than, doing curl localhost:9200/_cat/indices or viewing at browser should be a index name, this name must be put on the index patter of kibana site to collect them.

### Start filebeat for push the logs or configured resources.

	service filebeat start

### For verify that Elasticsearch is receiving this data do:

	curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty'


### Extra!! (fix vm.max_map_count error):

	bootstrap checks failed
	initial heap size [268435456] not equal to maximum heap size [2147483648]; this can cause resize pauses and prevents mlockall from locking the entire heap
	max virtual memory areas vm.max_map_count [65530] likely too low, increase to at least [262144]

	Do (/etc/sysctl.conf):

	sysctl -w vm.max_map_count=262144
