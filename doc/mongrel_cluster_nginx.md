

# Ruby on Rails API deployment on mongrel + mongel_cluster + nginx stack

## mongrel + mongrel_cluster setup

### mongrel installation
$ sudo gem1.8 install mongrel

### mongrel_cluster installation
$ sudo gem1.8 install mongrel_cluster

### mongrel_cluster configuration
$ cd /home/ayaz/dashboard/
$ sudo mongrel_rails cluster::configure -e production -p 3001 -N 4 -c /home/ayaz/dashboard -a 0.0.0.0

### mongrel_cluster basic commands
$ sudo mongrel_rails cluster::start
$ sudo mongrel_rails cluster::stop
$ sudo mongrel_rails cluster::restart

### mongrel basic commands
$ sudo mongrel_rails start -e production -p 3000 -d 
$ sudo mongrel_rails stop



## nginx setup
$ sudo apt-get install -y nginx
$ sudo cat > /etc/nginx/conf.d/mcoapi.conf <<EOF
  gzip_min_length  1100;
  gzip_buffers     4 8k;
  gzip_types       text/plain;

  upstream mongrel {
    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    server 127.0.0.1:3003;
    server 127.0.0.1:3004;
  }
EOF
$ sudo cat > /etc/nginx/sites-available/mcoapi <<EOF
  server {
    listen       3000;
    #server_name  example.com;
    root         /home/ayaz/dashboard/;
    #index        index.html index.htm;

    #try_files  $uri/index.html $uri.html $uri @mongrel;
    try_files  $uri/ $uri @mongrel;

    location @mongrel {
      proxy_set_header  X-Real-IP        $remote_addr;
      proxy_set_header  X-Forwarded-For  $proxy_add_x_forwarded_for;
      proxy_set_header  Host             $http_host;
      proxy_redirect    off;
      proxy_pass        http://mongrel;
    }
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
      root   html;
    }
  }
EOF
$ sudo ln -s /etc/nginx/sites-available/mcoapi /etc/nginx/sites-enabled/mcoapi
$ sudo nginx -t

## Starting nginx and mongrel_cluster
$ sudo mongrel_rails cluster::start
$ sudo /etc/init.d/nginx start

## Stopping nginx and mongrel_cluster
$ sudo /etc/init.d/nginx stop
$ sudo mongrel_rails cluster::stop


