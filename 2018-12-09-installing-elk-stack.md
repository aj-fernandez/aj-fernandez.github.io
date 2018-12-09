---
layout: post
title:  "Installink ELK in Debian 9"
categories: [labs]
tags: [elk, debian]
---

# Installing Elasticsearch on Hewlett Packard ML350 G5
![alt 
text](https://ydevs.com/wp-content/uploads/2017/10/logos-stack-elk.png)
### Update and install required packages

	sudo apt update && apt-get -y upgrade
	sudo apt install apt-transport-https software-properties-common 
wget

### Install jdk oracle java (required by Elastichsearch & Kibana)

	sudo apt install openjdk-8-jdk

	wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | 
sudo apt-key add -
	echo "deb https://artifacts.elastic.co/packages/6.x/apt stable 
main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
	
	sudo apt update
	sudo apt install elasticsearch

### Limiting listen interfaces for Elasticsearch (not required xD)

 Edit /etc/elasticsearch/elasticsearch.yml

	network.host: localhost (localhost can be changed for an IP)

### Restart Elasticsearch for load changes and enable for load at new 
boots

	systemctl restart elasticsearch
	systemctl enable elasticsearch

### Checking the installation of Elasticsearch, this must show a JSON 
doc

	curl -X GET http://localhost:9200

### Install plugin required for Apache2 and Nginx modules among others:

On: /usr/share/elasticsearch
	
	bin/elasticsearch-plugin install ingest-user-agent
	bin/elasticsearch-plugin install ingest-geoip

### Installing Kibana

	apt install kibana

### Restricting remote access to Kibana
	
Edit /etc/kibana/kibana.yml
	
	server.host: "localhost"

### Restart Kibana for load changes and enable for load at new boots

	systemctl restart kibana
	systemctl enable kibana

### Usin Nginx like reverse proxy to access Kibana from public IP

- Intall Nginx web server

		apt install nginx

 - Basic authentication file with openssl command

		echo "admin:$(openssl passwd -apr1 typeHereThePassword)" 
| sudo tee -a /etc/nginx/htpasswd.kibana

This is a virtual host config file, delete the default file and create 
/etc/nginx/sites-available/kibana:
		
		server {
		    listen 80 default_server;
		    server_name _;
		    return 301 https://$server_name$request_uri;
		}

		server {
		    listen 443 default_server ssl http2;
 
		    server_name _;
 
		    ssl_certificate 
/etc/ssl/certs/ssl-cert-snakeoil.pem;
		    ssl_certificate_key 
/etc/ssl/private/ssl-cert-snakeoil.key;
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

Activate this site creating the simbolic link, test it and 
restart&enable:

		sudo ln -s /etc/nginx/sites-available/kibana 
/etc/nginx/sites-enabled/kibana
		sudo nginx -t
		sudo systemctl restart nginx
		sudo systemctl enable nginx

### Install Logstash, restart&enable
	
	sudo systemctl restart logstash
	sudo systemctl enable logstash
	
	Config file used by default: /etc/logstash/startup.options
	
Validating Logstash setup

		sudo -u logstash /usr/share/logstash/bin/logstash 
--path.settings /etc/logstash -t

### Install Filebeat on forwarders-nodes

 Home path: [/usr/share/filebeat] Config path: [/etc/filebeat] Data 
path: [/var/lib/filebeat] Logs path: [/var/log/filebeat]

	curl -L -O 
https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.5.2-amd64.deb

	sudo dpkg -i filebeat-6.5.2-amd64.deb

	systemctl status filebeat

	systemctl enable filebeat

 - Config host.elastichsearch in /etc/filebeat/filebeat.yml:

		output.elasticsearch:
		  hosts: ["myEShost:9200"]

- Add credentials if elasctichsearch or kibana have been secured:

		output.elasticsearch:
		  hosts: ["myEShost:9200"]
		  username: "filebeat_internal"
		  password: "typePassword"

		setup.kibana:
		  host: "mykibanahost:5601"
		  username: "myKibanaUser"
		  password: "typePassword"

[Filebeat config official 
guide](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-configuration.html)
### Enable modules that you want to run

- Enable them:

		filebeat modules enable system nginx mysql apache2 etc

- To see a list of enabled and disabled modules:

		filebeat modules list

**Config modules: /etc/filebeat/modules.d/system.yml**

### Set up initial environment.
- Run:

		filebeat setup -e

The setup command loads the recommended index template for writing to 
Elasticsearch and deploys the sample dashboards (if available) for 
visualizing the data in Kibana. This is a one-time setup step.

The -e flag is optional and sends output to standard error instead of 
syslog.

After than, doing **curl localhost:9200/_cat/indices** or viewing at 
browser should be a index name, this name must be put on the index 
patter of kibana site to collect them.

### Start filebeat for push the logs or configured resources.
- Run:

		service filebeat start

### For verify that Elasticsearch is receiving this data:

- Run:

		curl -XGET 
'http://localhost:9200/filebeat-*/_search?pretty'

And the output of curl should show something like this, the json docs 
created for each event generated by our monitorized logs.

	 "@timestamp" : "2018-11-26T10:58:05.000Z",
          "system" : {
            "syslog" : {
              "hostname" : "debianbackup",
              "program" : "kernel",
              "message" : "[1037924.891748] [UFW BLOCK] IN=enp3s0 OUT= 
MAC=01:00:5e:00:00:fb:b8:53:ac:9e:b5:f6:08:00 SRC=10.65.3.141 
DST=224.0.0.251 LEN=32 TOS=0x00 PREC=0x00 TTL=1 ID=50427 PROTO=2 ",
              "timestamp" : "Nov 26 10:58:05"
            }
          },
          "beat" : {
            "hostname" : "debianbackup",
            "name" : "debianbackup",
            "version" : "6.5.2"
          },
          "host" : {
            "os" : {
              "codename" : "stretch",
              "family" : "debian",
              "version" : "9 (stretch)",
              "platform" : "debian"
            },
            "containerized" : false,
            "name" : "debianbackup",
            "id" : "05708074cb5b49a3a1e5624260d5f072",
            "architecture" : "x86_64"
          }
        }
      },
      {
        "_index" : "filebeat-6.5.2-2018.12.08",
        "_type" : "doc",
        "_id" : "kl7Hj2cB3NM3oblOBygf",
        "_score" : 1.0,
        "_source" : {
          "offset" : 527409,
          "prospector" : {
            "type" : "log"
          },
          "source" : "/var/log/syslog",
          "fileset" : {
            "module" : "system",
            "name" : "syslog"
          },
          "input" : {
            "type" : "log"
          },
 

It is so interesting and, above all, useful, that we can interact with 
Elasticshearch using a RESTFul API. Thanks to this we can, using a 
browser, a programming language or like in the previous section, using 
**curl** on a shell, interact with Elasticsearch over the port 9200 in 
an easy way.

On the [project 
website](https://www.elastic.co/guide/en/elasticsearch/guide/current/_talking_to_elasticsearch.html) 
we can find what is necessary to develop our queries using curl.
### Extra, fixing "vm.max_map_count error":

	bootstrap checks failed
	initial heap size [268435456] not equal to maximum heap size 
[2147483648]; this can cause resize pauses and prevents mlockall from 
locking the entire heap
	max virtual memory areas vm.max_map_count [65530] likely too 
low, increase to at least [262144]

Do (/etc/sysctl.conf):

	sysctl -w vm.max_map_count=262144

